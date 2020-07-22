from CommonServerPython import *

''' IMPORTS '''
from collections import defaultdict
from typing import Any, Dict
import httplib2
import urllib.parse
from oauth2client import service_account

# A request will be tried 3 times if it fails at the socket/connection level
httplib2.RETRIES = 3

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']

BACKSTORY_API_V1_URL = 'https://backstory.googleapis.com/v1'

ISO_DATE_REGEX = (r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):'
                  r'([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?Z$')

CHRONICLE_OUTPUT_PATHS = {
    'Asset': 'GoogleChronicleBackstory.Asset(val.{0} && val.{0} == obj.{0})',
    'Iocs': 'GoogleChronicleBackstory.Iocs(val.Artifact && val.Artifact == obj.Artifact)',
    'IocDetails': 'GoogleChronicleBackstory.IocDetails(val.IoCQueried && val.IoCQueried == obj.IoCQueried)',
    'Ip': 'GoogleChronicleBackstory.IP(val.IoCQueried && val.IoCQueried == obj.IoCQueried)',
    'Domain': 'GoogleChronicleBackstory.Domain(val.IoCQueried && val.IoCQueried == obj.IoCQueried)',
    'Alert': 'GoogleChronicleBackstory.Alert(val.AssetName && val.AssetName == obj.AssetName)',
    'Events': 'GoogleChronicleBackstory.Events'
}

ARTIFACT_NAME_DICT = {
    'domain_name': 'Domain',
    'hash_sha256': 'SHA256',
    'hash_sha1': 'SHA1',
    'hash_md5': 'MD5',
    'destination_ip_address': 'IP'
}

ASSET_IDENTIFIER_NAME_DICT = {
    'host name': 'hostname',
    'ip address': 'asset_ip_address',
    'mac address': 'mac',
    'product id': 'product_id',
}

HOST_CTX_KEY_DICT = {
    'hostname': 'Hostname',
    'assetIpAddress': 'IP',
    'productId': 'ID',
    'MACAddress': 'MACAddress'
}

CONTEXT_KEY_DICT = {
    'hostname': 'HostName',
    'assetIpAddress': 'IpAddress',
    'productId': 'ProductId',
    'MACAddress': 'MACAddress'
}

STANDARD_CTX_KEY_MAP = {
    'ip': 'Address',
    'domain': 'Name',
    'file': 'Name'
}

DBOT_SCORE_MAPPING = {
    0: 'Unknown',
    1: 'Good',
    2: 'Suspicious',
    3: 'Malicious'
}

CONFIDENCE_LEVEL_PRIORITY = {
    'unknown_severity': 0,
    'informational': 1,
    'low': 2,
    'medium': 3,
    'high': 4
}

SEVERITY_MAP = {
    'unspecified': 0,
    'low': 1,
    'medium': 2,
    'high': 3
}

''' CLIENT CLASS '''


class Client:
    """
    Client to use in integration to fetch data from Chronicle Backstory

    requires service_account_credentials : a json formatted string act as a token access
    """

    def __init__(self, params: Dict[str, Any], proxy, disable_ssl):
        encoded_service_account = str(params.get('service_account_credential'))
        service_account_credential = json.loads(encoded_service_account, strict=False)
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(service_account_credential,
                                                                                       scopes=SCOPES)
        self.http_client = credentials.authorize(get_http_client(proxy, disable_ssl))


''' HELPER FUNCTIONS '''


def get_http_client(proxy, disable_ssl):
    """
    Constructs HTTP Client.

    :param proxy: if proxy is enabled, http client with proxy is constructed
    :param disable_ssl: insecure
    :return: http_client object
    """

    proxy_info = {}
    if proxy:
        proxies = handle_proxy()
        if not proxies.get('https', True):
            raise Exception('https proxy value is empty. Check Demisto server configuration' + str(proxies))
        https_proxy = proxies['https']
        if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
            https_proxy = 'https://' + https_proxy
        parsed_proxy = urllib.parse.urlparse(https_proxy)
        proxy_info = httplib2.ProxyInfo(
            proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
            proxy_host=parsed_proxy.hostname,
            proxy_port=parsed_proxy.port,
            proxy_user=parsed_proxy.username,
            proxy_pass=parsed_proxy.password)
    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=disable_ssl)


def validate_response(client, url, method='GET'):
    """
    Get response from Chronicle Search API and validate it.

    :param client: object of client class
    :type client: object of client class

    :param url: url
    :type url: str

    :param method: HTTP request method
    :type method: str

    :return: response
    """
    for _ in range(3):
        raw_response = client.http_client.request(url, method)

        if not raw_response:
            raise ValueError('Technical Error while making API call to Chronicle. Empty response received')
        if raw_response[0].status == 500:
            raise ValueError('Internal server error occurred, please try again later')
        if raw_response[0].status == 429:
            demisto.debug('API Rate limit exceeded. Retrying in {} seconds...'.format(1))
            time.sleep(1)
            continue
        if raw_response[0].status != 200:
            return_error(
                'Status code: {}\nError: {}'.format(raw_response[0].status, parse_error_message(raw_response[1])))
        try:
            response = json.loads(raw_response[1])
            return response
        except json.decoder.JSONDecodeError:
            raise ValueError('Invalid response format while making API call to Chronicle. Response not in JSON format')
    else:
        raise ValueError('API rate limit exceeded. Try again later.')


def get_params_for_reputation_command():
    """
    This function gets the Demisto parameters related to reputation command

    :return: Dict of parameters related to reputation command
    :rtype: dict
    """
    # fetching parameters for reputation command
    malicious_category_list = demisto.params().get('malicious_categories')
    suspicious_category_list = demisto.params().get('suspicious_categories')
    malicious_category_list = malicious_category_list if malicious_category_list is not None else ''
    suspicious_category_list = suspicious_category_list if suspicious_category_list is not None else ''

    # create list of malicious and suspicious categories based on entered comma separated values
    override_malicious_categories = [malicious_category.strip().lower() for malicious_category in
                                     malicious_category_list.split(',')]
    override_suspicious_categories = [suspicious_category.strip().lower() for suspicious_category in
                                      suspicious_category_list.split(',')]

    malicious_severity_list = demisto.params().get('override_severity_malicious')
    suspicious_severity_list = demisto.params().get('override_severity_suspicious')
    override_malicious_severity = malicious_severity_list if malicious_severity_list is not None else ''
    override_suspicious_severity = suspicious_severity_list if suspicious_severity_list is not None else ''

    override_malicious_confidence_score = demisto.params().get('override_confidence_score_malicious_threshold')
    override_suspicious_confidence_score = demisto.params().get('override_confidence_score_suspicious_threshold')

    malicious_confidence_score_threshold_str = demisto.params().get('override_confidence_level_malicious')
    suspicious_confidence_score_threshold_str = demisto.params().get(
        'override_confidence_level_suspicious')

    override_malicious_confidence_score_str = malicious_confidence_score_threshold_str \
        if malicious_confidence_score_threshold_str is not None else ''
    override_suspicious_confidence_score_str = suspicious_confidence_score_threshold_str \
        if suspicious_confidence_score_threshold_str is not None else ''

    return {
        'malicious_categories': override_malicious_categories,
        'suspicious_categories': override_suspicious_categories,
        'override_severity_malicious': override_malicious_severity,
        'override_severity_suspicious': override_suspicious_severity,
        'override_confidence_score_malicious_threshold': override_malicious_confidence_score,
        'override_confidence_score_suspicious_threshold': override_suspicious_confidence_score,
        'override_confidence_level_malicious': override_malicious_confidence_score_str,
        'override_confidence_level_suspicious': override_suspicious_confidence_score_str
    }


def validate_configuration_parameters(param: Dict[str, Any]):
    """
    Check whether entered configuration parameters are valid or not.

    :type param: dict
    :param param: Dictionary of demisto configuration parameter

    :return: raise ValueError if any configuration parameter is not in valid format else returns None
    :rtype: None
    """
    # get configuration parameters
    service_account_json = param.get('service_account_credential', '')
    fetch_days = param.get('first_fetch_time_interval_days', '3 days').lower()
    page_size = param.get('fetch_limit', '10')

    try:
        # validate service_account_credential configuration parameter
        json.loads(service_account_json, strict=False)

        # validate fetch_limit configuration parameter
        if not page_size.isdigit():
            raise ValueError('Incidents fetch limit must be a number')

        # validate first_fetch_time_interval_days parameter
        range_split = fetch_days.split(' ')
        if len(range_split) != 2:
            raise ValueError('First fetch days must be "number time_unit", '
                             'examples: (10 days, 6 months, 1 year, etc.)')

        if not range_split[0].isdigit():
            raise ValueError('First fetch days must be "number time_unit", '
                             'examples: (10 days, 6 months, 1 year, etc.)')
        if not range_split[1] in ['day', 'days', 'month', 'months', 'year', 'years']:
            raise ValueError('First fetch days field\'s unit is invalid. Must be in day(s), month(s) or year(s)')

        # validate override_confidence_score_malicious_threshold and override_confidence_score_suspicious_threshold
        # parameters
        reputation_related_params = get_params_for_reputation_command()
        if reputation_related_params['override_confidence_score_malicious_threshold'] is not None \
                and reputation_related_params['override_confidence_score_malicious_threshold'] != '' \
                and not reputation_related_params['override_confidence_score_malicious_threshold'].isnumeric():
            raise ValueError('Confidence Score Threshold must be a number')
        if reputation_related_params['override_confidence_score_suspicious_threshold'] is not None \
                and reputation_related_params['override_confidence_score_suspicious_threshold'] != '' \
                and not reputation_related_params['override_confidence_score_suspicious_threshold'].isnumeric():
            raise ValueError('Confidence Score Threshold must be a number')

    except json.decoder.JSONDecodeError:
        raise ValueError('User\'s Service Account JSON has invalid format')


def validate_start_end_date(start_date, end_date=None, reference_time=None):
    """
    Check whether the start_date and end_date provided are in valid ISO Format(e.g. 2019-10-17T00:00:00Z)
    Check whether start_date is not later than end_date.
    Check whether start_date and end_date are not a future date.

    :type start_date: string
    :param start_date: date

    :type end_date: string
    :param end_date: date

    :type reference_time: string
    :param reference_time: date

    :return: raise ValueError if validation fails, else return None
    :rtype: None
    """
    # checking date format
    try:
        datetime.strptime(start_date, '%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        raise ValueError('Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z')

    # checking future date
    today = datetime.utcnow().strftime(DATE_FORMAT)
    if start_date > today:
        raise ValueError('Invalid start time, can not be greater than current UTC time')

    if end_date:
        # checking date format
        try:
            datetime.strptime(end_date, '%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            raise ValueError('Invalid end time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z')

        # checking future date
        if end_date > today:
            raise ValueError('Invalid end time, can not be greater than current UTC time')

        # checking end date must be lower than start date
        if start_date > end_date:
            raise ValueError('End time must be later than Start time')

    if reference_time:
        # checking date format
        try:
            datetime.strptime(reference_time, '%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            raise ValueError('Invalid reference time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z')


def validate_page_size(page_size):
    """
    Validate that page size parameter is in numeric format or not

    :type page_size: str
    :param page_size: this value will be check as numeric or not

    :return: True if page size is valid  else raise ValueError
    :rtype: bool
    """
    if not page_size or not str(page_size).isdigit() or int(page_size) == 0:
        raise ValueError('Page size must be a non-zero numeric value')
    return True


def validate_preset_time_range(value):
    """
    Validate that preset_time_range parameter is in valid format or not
    Strip the keyword 'Last' to extract the date range if validation is through.

    :type value: str
    :param value: this value will be check as valid or not

    :return: 1 Day, 7 Days, 15 Days, 30 Days or ValueError
    :rtype: string or Exception
    """
    value_split = value.split(' ')
    try:
        if value_split[0].lower() != 'last':
            raise ValueError(
                'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", '
                '"Last 15 days" and "Last 30 days"')

        day = int(value_split[1])

        if day not in [1, 7, 15, 30]:
            raise ValueError(
                'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", '
                '"Last 15 days" and "Last 30 days"')

        if value_split[2].lower() not in ['day', 'days']:
            raise ValueError(
                'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", '
                '"Last 15 days" and "Last 30 days"')
    except Exception:
        raise ValueError(
            'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", '
            '"Last 15 days" and "Last 30 days"')
    return value_split[1] + ' ' + value_split[2].lower()


def get_chronicle_default_date_range(days='3 days'):
    """
    This function returns Chronicle Backstory default date range(last 3 days)

    :return: start_date, end_date (ISO date in UTC)
    :rtype: string
    """
    start_date, end_date = parse_date_range(days)
    return start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)


def get_artifact_type(value):
    """
    This function derives the input value's artifact type based on regex match.
    The returned artifact_type is complaint with the Search API.

    :type value: string
    :param value: artifact value

    :return: domain_name, hash_sha256, hash_sha1, hash_md5, destination_ip_address or raise ValueError
    :rtype: string or Exception
    """
    # checking value if is valid ip
    if is_ip_valid(value, True):
        return 'destination_ip_address'
    else:
        hash_type = get_hash_type(value)  # checking value if is MD5, SHA-1 or SHA-256

        if hash_type != 'Unknown':
            return 'hash_' + hash_type

        return 'domain_name'  # if it's not IP or hash then it'll be considered as domain_name


def parse_assets_response(response: Dict[str, Any], artifact_type, artifact_value):
    """
    parse response of list assets within the specified time range.

    :type response: Dict
    :param response: it is response of assets

    :type artifact_type: String
    :param artifact_type: type of artifact (domain_name, hash_sha256, hash_sha1, hash_md5, destination_ip_address)

    :type artifact_value: String
    :param artifact_value: value of artifact

    :return: command output
    :rtype: Tuple
    """

    asset_list = response.get('assets', [])
    context_data = defaultdict(list)  # type: Dict[str, Any]
    tabular_data_list = list()
    host_context = list()

    for data in asset_list:
        # Extract the asset identifier key from response.
        # It could be one of Hostname, IpAddress, Mac
        asset_dict = data.get('asset', {})
        if not asset_dict:
            demisto.debug('Empty asset details found in response. Skipping this record.')
            continue

        asset_identifier_key = list(asset_dict.keys())[0]
        asset_identifier_value = list(asset_dict.values())[0]

        # The asset identifier keys for MAC and product ID are not definitive.
        # Using string match, to ascertain the asset identifier in such case.
        if asset_identifier_key not in CONTEXT_KEY_DICT:
            if "mac" in asset_identifier_key.lower():
                asset_identifier_key = 'MACAddress'
            elif "product" in asset_identifier_key.lower():
                asset_identifier_key = 'productId'
            else:
                demisto.debug('Unknown asset identifier found - {}. Skipping this asset'.format(asset_identifier_key))
                continue
        ctx_primary_key = CONTEXT_KEY_DICT[asset_identifier_key]

        # Preparing GCB custom context
        gcb_context_data = dict()
        gcb_context_data[ctx_primary_key] = asset_identifier_value
        gcb_context_data['FirstAccessedTime'] = data.get('firstSeenArtifactInfo', {}).get('seenTime', '')
        gcb_context_data['LastAccessedTime'] = data.get('lastSeenArtifactInfo', {}).get('seenTime', '')
        gcb_context_data['Accessed' + ARTIFACT_NAME_DICT[artifact_type]] = artifact_value
        context_data[CHRONICLE_OUTPUT_PATHS['Asset'].format(ctx_primary_key)].append(gcb_context_data)

        # Response for HR
        tabular_data_dict = dict()
        tabular_data_dict['Host Name'] = asset_identifier_value if asset_identifier_key == 'hostname' else '-'
        tabular_data_dict['Host IP'] = asset_identifier_value if asset_identifier_key == 'assetIpAddress' else '-'
        tabular_data_dict['Host MAC'] = asset_identifier_value if asset_identifier_key == 'MACAddress' else '-'
        tabular_data_dict['First Accessed Time'] = data.get('firstSeenArtifactInfo', {}).get('seenTime', '-')
        tabular_data_dict['Last Accessed Time'] = data.get('lastSeenArtifactInfo', {}).get('seenTime', '-')
        tabular_data_list.append(tabular_data_dict)

        # Populating Host context for list of assets
        host_context.append({HOST_CTX_KEY_DICT[asset_identifier_key]: asset_identifier_value})
    return context_data, tabular_data_list, host_context


def get_default_command_args_value(args: Dict[str, Any], date_range=None):
    """
    returns and validate commands argument default values as per Chronicle Backstory

    :type args: dict
    :param args: contain all arguments for command

    :type date_range: string
    :param date_range: The date range to be parsed

    :return : start_time, end_time, page_size
    :rtype : datetime, datetime, int̥
    """
    preset_time_range = args.get('preset_time_range', None)
    if preset_time_range:
        preset_time_range = validate_preset_time_range(preset_time_range)
        start_time, end_time = get_chronicle_default_date_range(preset_time_range)
    else:
        if date_range is None:
            date_range = '3 days'
        start_time, end_time = get_chronicle_default_date_range(days=date_range)
        start_time = args.get('start_time', start_time)
        end_time = args.get('end_time', end_time)
    page_size = args.get('page_size', 10000)
    validate_page_size(page_size)
    if args.get('reference_time', ''):
        validate_start_end_date(start_time, end_time, args.get('reference_time', ''))
    else:
        validate_start_end_date(start_time, end_time)

    return start_time, end_time, page_size


def parse_error_message(error):
    """
    Extract error message from error object

    :type error: bytearray
    :param error: Error byte response to be parsed

    :return: error message
    :rtype: str
    """
    try:
        json_error = json.loads(error)
    except json.decoder.JSONDecodeError:
        demisto.debug(
            'Invalid response received from Chronicle Search API. Response not in JSON format. Response - {}'.format(
                error))
        raise ValueError('Invalid response received from Chronicle Search API. Response not in JSON format.')

    if json_error.get('error', {}).get('code') == 403:
        return 'Permission denied'
    return json_error.get('error', {}).get('message', '')


def get_informal_time(date):
    """
    convert to informal time from date to current time

    :type date: string
    :param date: string of datetime object

    :return: informal time from date to current time
    :rtype: str
    """
    current_time = datetime.utcnow()
    previous_time = parse_date_string(date)

    total_time = (current_time - previous_time).total_seconds()

    if 0 < total_time < 60:
        return 'a second ago' if total_time == 1 else str(total_time) + ' seconds ago'
    total_time = round(total_time / 60)
    if 0 < total_time < 60:
        return 'a minute ago' if total_time == 1 else str(total_time) + ' minutes ago'
    total_time = round(total_time / 60)
    if 0 < total_time < 24:
        return 'an hour ago' if total_time == 1 else str(total_time) + ' hours ago'
    total_time = round(total_time / 24)
    if 0 < total_time < 31:
        return 'a day ago' if total_time == 1 else str(total_time) + ' days ago'
    total_time = round(total_time / 31)
    if 0 < total_time < 12:
        return 'a month ago' if total_time == 1 else str(total_time) + ' months ago'
    total_time = round((total_time * 31) / 365)
    return 'a year ago' if total_time == 1 else str(total_time) + ' years ago'


def parse_list_ioc_response(ioc_matches):
    """
    Parse response of list iocs within the specified time range.
    Constructs the Domain Standard context, Human readable and EC.

    :type ioc_matches: List
    :param ioc_matches: it is list of iocs

    :return: gives dict that contain hr_ioc_matches dict for human readable,domain_std_context and contexts dict for
        context data
    :rtype: Dict
    """
    domain_std_context = []
    hr_ioc_matches = []
    context = []
    for ioc_match in ioc_matches:
        sources = []
        # get details from response
        domain = ioc_match.get('artifact', {}).get('domainName', '')
        ingest_time = ioc_match.get('iocIngestTime', '')
        first_seen_time = ioc_match.get('firstSeenTime', '')
        last_seen_time = ioc_match.get('lastSeenTime', '')
        for ioc_rep_source in ioc_match.get('sources', []):
            source = ioc_rep_source.get('source', '')
            confidence = ioc_rep_source.get('confidenceScore', {}).get('normalizedConfidenceScore', 'unknown')
            severity = ioc_rep_source.get('rawSeverity', '')
            category = ioc_rep_source.get('category', '')

            # prepare normalized dict for human readable
            hr_ioc_matches.append({
                'Domain': '[{}]({})'.format(domain, ioc_match.get('uri', [''])[0]),
                'Category': category,
                'Source': source,
                'Confidence': confidence,
                'Severity': severity,
                'IOC ingest time': get_informal_time(ingest_time),
                'First seen': get_informal_time(first_seen_time),
                'Last seen': get_informal_time(last_seen_time),
            })

            sources.append({
                'Category': category,
                'IntRawConfidenceScore': ioc_rep_source.get('confidenceScore', {}).get('intRawConfidenceScore', 0),
                'NormalizedConfidenceScore': confidence,
                'RawSeverity': severity,
                'Source': source
            })

        # prepare context standard data for Domain
        domain_std_context.append({'Name': domain})

        # prepare context data for IoCs
        context.append({
            'Artifact': domain,
            'IocIngestTime': ingest_time,
            'FirstAccessedTime': first_seen_time,
            'LastAccessedTime': last_seen_time,
            'Sources': sources
        })

    return {'hr_ioc_matches': hr_ioc_matches, 'domain_std_context': domain_std_context, 'context': context}


def is_category_malicious(category, reputation_params):
    """
        determine if category is malicious in reputation_params
    """
    return category and category.lower() in reputation_params['malicious_categories']


def is_severity_malicious(severity, reputation_params):
    """
        determine if severity is malicious in reputation_params
    """
    return severity and severity.lower() in reputation_params['override_severity_malicious']


def is_confidence_score_malicious(confidence_score, params):
    """
        determine if confidence score is malicious in reputation_params
    """
    return is_int_type_malicious_score(confidence_score, params) or is_string_type_malicious_score(confidence_score,
                                                                                                   params)


def is_string_type_malicious_score(confidence_score, params):
    """
        determine if string type confidence score is malicious in reputation_params
    """
    return not isinstance(confidence_score, int) and CONFIDENCE_LEVEL_PRIORITY.get(
        params['override_confidence_level_malicious'], 10) <= CONFIDENCE_LEVEL_PRIORITY.get(confidence_score.lower(),
                                                                                            -1)


def is_int_type_malicious_score(confidence_score, params):
    """
        determine if integer type confidence score is malicious in reputation_params
    """
    return params['override_confidence_score_malicious_threshold'] and isinstance(confidence_score, int) and int(
        params['override_confidence_score_malicious_threshold']) <= confidence_score


def is_category_suspicious(category, reputation_params):
    """
        determine if category is suspicious in reputation_params
    """
    return category and category.lower() in reputation_params['suspicious_categories']


def is_severity_suspicious(severity, reputation_params):
    """
        determine if severity is suspicious in reputation_params
    """
    return severity and severity.lower() in reputation_params['override_severity_suspicious']


def is_confidence_score_suspicious(confidence_score, params):
    """
        determine if confidence score is suspicious in reputation_params
    """
    return is_int_type_suspicious_score(confidence_score, params) or is_string_type_suspicious_score(confidence_score,
                                                                                                     params)


def is_string_type_suspicious_score(confidence_score, params):
    """
        determine if string type confidence score is suspicious in reputation_params
    """
    return not isinstance(confidence_score, int) and CONFIDENCE_LEVEL_PRIORITY.get(
        params['override_confidence_level_suspicious'], 10) <= CONFIDENCE_LEVEL_PRIORITY.get(confidence_score.lower(),
                                                                                             -1)


def is_int_type_suspicious_score(confidence_score, params):
    """
        determine if integer type confidence score is suspicious in reputation_params
    """
    return params['override_confidence_score_suspicious_threshold'] and isinstance(confidence_score, int) and int(
        params['override_confidence_score_suspicious_threshold']) <= confidence_score


def evaluate_dbot_score(category, severity, confidence_score):
    """
    Calculate the dbot score according to category, severity and confidence score configured.

    :type category: str
    :param category: category received in the response of list-ioc-details endpoint

    :type severity: str
    :param severity: severity received in the response of list-ioc-details endpoint

    :type confidence_score: int or str
    :param confidence_score: confidence_score received in the response of list-ioc-details endpoint

    :return: the function returns dbot score based on the entered parameters.
    :rtype: int
    """
    params = get_params_for_reputation_command()

    dbot_score = 0

    # Check if the category belongs to configured Malicious category/severity/threshold score.
    if is_category_malicious(category, params) or is_severity_malicious(severity, params) \
            or is_confidence_score_malicious(confidence_score, params):
        dbot_score = 3

    # Check if the category belongs to configured Suspicious category/severity/threshold score.
    elif is_category_suspicious(category, params) or is_severity_suspicious(severity, params) \
            or is_confidence_score_suspicious(confidence_score, params):
        dbot_score = 2

    return dbot_score


def get_context_for_ioc_details(sources, artifact_indicator, artifact_type, is_reputation_command=True):
    """
    Generate context data for reputation command and ioc details command

    :type sources: list
    :param sources: list of the sources getting response from listiocdetails endpoint

    :type artifact_indicator: str
    :param artifact_indicator: inputted artifact indicator

    :type artifact_type: str
    :param artifact_type: the type of artifact

    :type is_reputation_command: bool
    :param is_reputation_command: true if the command is execute for reputation command, default is true

    :return: returns dict of context data, human readable, and reputation
    :rtype: dict
    """
    dbot_context = {}  # type: Dict[str, Any]
    standard_context = {}  # type: Dict[str, Any]
    source_data_list = []
    hr_table_data = []

    # To hold the max dbot score across sources.
    dbot_score_max = 0
    for source in sources:
        category = source.get('category')
        severity = source.get('rawSeverity')

        # if confidence score is not in numeric value, then it set confidence score will be set to 0
        confidence_score = source.get('confidenceScore', {}).get('strRawConfidenceScore')
        if confidence_score and confidence_score.isnumeric():
            confidence_score = int(confidence_score)

        if is_reputation_command:
            # Highest confidence score across the sources is considered for dbot_score
            source_dbot_score = evaluate_dbot_score(category, severity, confidence_score)
            dbot_score_max = source_dbot_score if source_dbot_score > dbot_score_max else dbot_score_max

        # prepare table content for Human Readable Data
        hr_table_row = {
            'Domain': '-',
            'IP Address': '-',
            'Category': category,
            'Confidence Score': confidence_score,
            'Severity': severity,
            'First Accessed Time': source.get('firstActiveTime'),
            'Last Accessed Time': source.get('lastActiveTime')
        }

        # Parsing the Addresses data to fetch IP and Domain data for context
        address_data = []
        for address in source.get('addresses', []):
            if address.get('domain'):
                address_data.append({
                    'Domain': address['domain'],
                    'Port': address.get('port', '')
                })
                hr_table_row['Domain'] = address['domain']
            if address.get('ipAddress'):
                address_data.append({
                    'IpAddress': address['ipAddress'],
                    'Port': address.get('port', '')
                })
                hr_table_row['IP Address'] = address['ipAddress']

        hr_table_data.append(hr_table_row)

        source_data_list.append({
            'Address': address_data,
            'Category': source.get('category', ''),
            'ConfidenceScore': confidence_score,
            'FirstAccessedTime': source.get('firstActiveTime', ''),
            'LastAccessedTime': source.get('lastActiveTime', ''),
            'Severity': source.get('rawSeverity', '')
        })

    # Setting standard context
    standard_context[STANDARD_CTX_KEY_MAP[artifact_type]] = artifact_indicator
    if is_reputation_command:
        # set dbot context
        dbot_context = {
            'Indicator': artifact_indicator,
            'Type': artifact_type,
            'Vendor': 'Google Chronicle Backstory',
            'Score': dbot_score_max
        }
        if dbot_score_max == 3:
            standard_context['Malicious'] = {
                'Vendor': 'Google Chronicle Backstory',
                'Description': 'Found in malicious data set'
            }

    context = {
        'IoCQueried': artifact_indicator,
        'Sources': source_data_list
    }

    return {
        'dbot_context': dbot_context,
        'standard_context': standard_context,
        'context': context,
        'hr_table_data': hr_table_data,
        'reputation': DBOT_SCORE_MAPPING[dbot_score_max]
    }


def parse_alert_info(alert_infos, filter_severity):
    """
    parses alert info of alerts
    :param alert_infos:
    :param filter_severity: will include alert_info if matches
    :return:
    """
    infos = []
    for alert_info in alert_infos:

        # filtering alert if supplied by the user in configuration settings. used for fetch-incidents only
        if filter_severity and filter_severity.lower() != alert_info.get('severity',
                                                                         '').lower() and filter_severity != 'ALL':
            continue

        info = {
            'Name': alert_info['name'],
            'SourceProduct': alert_info['sourceProduct'],
            'Severity': alert_info['severity'],
            'Timestamp': alert_info['timestamp'],
            'Uri': alert_info.get('uri', [''])[0]
        }
        infos.append(info)
    return infos, len(infos)


def get_ioc_domain_matches(client_obj, start_time, fetch_limit):
    """
    Calls list IOC API with :start_time, :end_time and :fetch_limit.
        filter_severity to filter out an alert after getting a response from API. Passing ALL will not filter any data
    :param client_obj perform API request
    :param start_time
    :param fetch_limit

    return events - list of dict representing events
    """

    request_url = '{}/ioc/listiocs?start_time={}&page_size={}'.format(BACKSTORY_API_V1_URL, start_time, fetch_limit)

    response_body = validate_response(client_obj, request_url)
    ioc_matches = response_body.get('response', {}).get('matches', [])
    parsed_ioc = parse_list_ioc_response(ioc_matches)
    return parsed_ioc['context']


def get_gcb_alerts(client_obj, start_time, end_time, fetch_limit, filter_severity):
    """
    Calls list alert API with :start_time, :end_time and :fetch_limit.
        filter_severity to filter out an alert after getting a response from API. Passing ALL will not filter any data
    :param client_obj perform API request
    :param start_time
    :param end_time
    :param fetch_limit
    :param filter_severity

    return events - list of dict representing events
    """
    request_url = '{}/alert/listalerts?start_time={}&end_time={}&page_size={}'.format(BACKSTORY_API_V1_URL, start_time,
                                                                                      end_time, fetch_limit)
    json_response = validate_response(client_obj, request_url)

    alerts = []
    for alert in json_response.get('alerts', []):
        # parsing each alert infos
        alert_info, alert_count = parse_alert_info(alert['alertInfos'], filter_severity)

        # skipping alerts with no alert_infos
        if alert_count == 0 and not alert_info:
            continue

        asset_alert = {
            'AssetName': list(alert['asset'].values())[0],
            'AlertCounts': alert_count,
            'AlertInfo': alert_info
        }
        alerts.append(asset_alert)
    return alerts


def reputation_operation_command(client_obj, indicator, reputation_function):
    """
    Common method for reputation commands to accept argument as a comma-separated values and converted into list
    and call specific function for all values.

    :param client_obj: object of client class
    :param indicator: comma-separated values or single value
    :param reputation_function: reputation command function. i.e ip_command and domain_command.

    :return: output of all value according to specified function.
    """
    artifacts = argToList(indicator, ',')
    for artifact in artifacts:
        return_outputs(*reputation_function(client_obj, artifact))


def group_infos_by_alert_asset_name(asset_alerts):
    """
    this method converts assets with multiple alerts into assets per asset_alert and
        returns both human readable and context.
    For an asset, group the asset_alert infos based on asset_alert name.
    Returns human readable and context data.

    :param asset_alerts: normalized asset alerts returned by Backstory.
    :return: both human readable and context format having asset per alerts object
    """

    unique_asset_alerts_hr = {}  # type: Dict[str,Any]
    unique_asset_alert_ctx = {}  # type: Dict[str,Any]
    for asset_alert in asset_alerts:
        for info in asset_alert['AlertInfo']:
            asset_alert_key = asset_alert['AssetName'] + '-' + info['Name']

            asset_alert_hr = unique_asset_alerts_hr.get(asset_alert_key, {})
            asset_alert_ctx = unique_asset_alert_ctx.get(asset_alert_key, {})

            if asset_alert_hr:
                # Re calculate First and Last seen time
                if info['Timestamp'] >= asset_alert_hr['Last Seen Ago']:
                    asset_alert_hr['Last Seen Ago'] = info['Timestamp']
                    asset_alert_hr['Last Seen'] = get_informal_time(info['Timestamp'])
                    asset_alert_ctx['LastSeen'] = info['Timestamp']
                elif info['Timestamp'] <= asset_alert_hr['First Seen Ago']:
                    asset_alert_hr['First Seen Ago'] = info['Timestamp']
                    asset_alert_hr['First Seen'] = get_informal_time(info['Timestamp'])
                    asset_alert_ctx['FirstSeen'] = info['Timestamp']
            else:
                asset_alert_hr['First Seen Ago'] = info['Timestamp']
                asset_alert_hr['First Seen'] = get_informal_time(info['Timestamp'])
                asset_alert_hr['Last Seen Ago'] = info['Timestamp']
                asset_alert_hr['Last Seen'] = get_informal_time(info['Timestamp'])

                asset_alert_ctx['FirstSeen'] = info['Timestamp']
                asset_alert_ctx['LastSeen'] = info['Timestamp']

            asset_alert_ctx.setdefault('Occurrences', []).append(info['Timestamp'])
            asset_alert_ctx['Alerts'] = asset_alert_hr['Alerts'] = asset_alert_ctx.get('Alerts', 0) + 1
            asset_alert_ctx['Asset'] = asset_alert['AssetName']
            asset_alert_ctx['AlertName'] = asset_alert_hr['Alert Names'] = info['Name']
            asset_alert_ctx['Severities'] = asset_alert_hr['Severities'] = info['Severity']
            asset_alert_ctx['Sources'] = asset_alert_hr['Sources'] = info['SourceProduct']

            asset_alert_hr['Asset'] = '[{}]({})'.format(asset_alert['AssetName'], info.get('Uri'))

            unique_asset_alert_ctx[asset_alert_key] = asset_alert_ctx
            unique_asset_alerts_hr[asset_alert_key] = asset_alert_hr

    return unique_asset_alerts_hr, unique_asset_alert_ctx


def convert_alerts_into_hr(events):
    """
    converts alerts into human readable by parsing alerts
    :param events:
    :return:
    """
    data = group_infos_by_alert_asset_name(events)[0].values()
    return tableToMarkdown('Security Alert(s)', list(data),
                           ['Alerts', 'Asset', 'Alert Names', 'First Seen', 'Last Seen', 'Severities',
                            'Sources'],
                           removeNull=True)


def get_asset_identifier_details(asset_identifier):
    """
    Return asset identifier detail such as hostname, ip, mac

    :param asset_identifier: A dictionary that have asset information
    :type asset_identifier: dict

    :return: asset identifier name
    :rtype: str
    """
    if asset_identifier.get('hostname', ''):
        return asset_identifier.get('hostname', '')
    if asset_identifier.get('ip', []):
        return '\n'.join(asset_identifier.get('ip', []))
    if asset_identifier.get('mac', []):
        return '\n'.join(asset_identifier.get('mac', []))
    return None


def get_more_information(event):
    """
    Get more information for event from response

    :param event: event details
    :type event: dict

    :return: queried domain, process command line, file use by process
    :rtype: str, str, str
    """
    queried_domain = ''
    process_command_line = ''
    file_use_by_process = ''

    if event.get('metadata', {}).get('eventType', '') == 'NETWORK_DNS':
        questions = event.get('network', {}).get('dns', {}).get('questions', [])
        for question in questions:
            queried_domain += '{}\n'.format(question.get('name', ''))

    if event.get('target', {}).get('process', {}).get('commandLine', ''):
        process_command_line += event.get('target', {}).get('process', {}).get('commandLine', '')

    if event.get('target', {}).get('process', {}).get('file', {}).get('fullPath', ''):
        file_use_by_process += event.get('target', {}).get('process', {}).get('file', {}).get('fullPath', '')

    return queried_domain, process_command_line, file_use_by_process


def get_context_for_events(events):
    """
    Convert response into Context data

    :param events: List of events
    :type events: list

    :return: list of context data
    """
    events_ec = []
    for event in events:
        event_dict = {}
        if 'metadata' in event.keys():
            event_dict.update(event.pop('metadata'))
        event_dict.update(event)
        events_ec.append(event_dict)

    return events_ec


def get_list_events_hr(events):
    """
    converts events response into human readable.

    :param events: list of events
    :type events: list

    :return: returns human readable string for gcb-list-events command
    :rtype: str
    """

    hr_dict = []
    for event in events:
        # Get queried domain, process command line, file use by process information
        more_info = get_more_information(event)

        hr_dict.append({
            'Event Timestamp': event.get('metadata', {}).get('eventTimestamp', ''),
            'Event Type': event.get('metadata', {}).get('eventType', ''),
            'Principal Asset Identifier': get_asset_identifier_details(event.get('principal', {})),
            'Target Asset Identifier': get_asset_identifier_details(event.get('target', {})),
            'Queried Domain': more_info[0],
            'Process Command Line': more_info[1],
            'File In Use By Process': more_info[2]
        })

    hr = tableToMarkdown('Event(s) Details', hr_dict,
                         ['Event Timestamp', 'Event Type', 'Principal Asset Identifier', 'Target Asset Identifier',
                          'Queried Domain', 'File In Use By Process', 'Process Command Line'], removeNull=True)
    return hr


''' REQUESTS FUNCTIONS '''


def test_function(client_obj, params: Dict[str, Any]):
    """
    Performs test connectivity by validating a valid http response

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type params:  Dict[str, Any]
    :param params: it contain configuration parameter

    :return: raise ValueError if any error occurred during connection
    :rtype: None
    """
    demisto.debug('Running Test having Proxy {}'.format(params.get('proxy')))
    request_url = '{}/ioc/listiocs?start_time=2019-10-15T20:37:00Z&page_size=1'.format(
        BACKSTORY_API_V1_URL)

    validate_response(client_obj, request_url)
    demisto.results('ok')


def gcb_list_iocs_command(client_obj, args: Dict[str, Any]):
    """
    List all of the IoCs discovered within your enterprise within the specified time range

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args:  Dict[str, Any]
    :param args: it contain arguments of gcb-list-ioc command

    :return: command output
    :rtype: (dict, dict, dict)
    """
    # retrieve arguments and validate it

    start_time, _, page_size = get_default_command_args_value(args)

    # Make a request
    request_url = '{}/ioc/listiocs?start_time={}&page_size={}'.format(
        BACKSTORY_API_V1_URL, start_time, page_size)
    json_data = validate_response(client_obj, request_url)

    # List of IoCs returned for further processing
    ioc_matches = json_data.get('response', {}).get('matches', [])
    if ioc_matches:
        ioc_matches_resp = parse_list_ioc_response(ioc_matches)

        # prepare human readable response
        hr = tableToMarkdown('IOC Domain Matches', ioc_matches_resp['hr_ioc_matches'],
                             ['Domain', 'Category', 'Source', 'Confidence', 'Severity', 'IOC ingest time',
                              'First seen', 'Last seen'], removeNull=True)
        # prepare entry context response
        ec = {
            outputPaths['domain']: ioc_matches_resp['domain_std_context'],
            CHRONICLE_OUTPUT_PATHS['Iocs']: ioc_matches_resp['context']
        }
        return hr, ec, json_data
    else:
        return '### No domain matches found', {}, {}


def gcb_assets_command(client_obj, args: Dict[str, str]):
    """
    This command will respond with a list of the assets which accessed the input artifact
    (ip, domain, md5, sha1, sha256) during the specified time.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args:  Dict[str, str]
    :param args: it contain arguments of gcb-list-ioc command

    :return: command output
    """

    artifact_value = args.get('artifact_value', '')
    artifact_type = get_artifact_type(artifact_value)

    start_time, end_time, page_size = get_default_command_args_value(args)

    request_url = '{}/artifact/listassets?artifact.{}={}&start_time={}&end_time={}&page_size={}'.format(
        BACKSTORY_API_V1_URL, artifact_type, urllib.parse.quote(artifact_value), start_time, end_time, page_size)

    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    if response and response.get('assets'):
        context_data, tabular_data, host_context = parse_assets_response(response, artifact_type,
                                                                         artifact_value)
        hr = tableToMarkdown('Artifact Accessed - {0}'.format(artifact_value), tabular_data,
                             ['Host Name', 'Host IP', 'Host MAC', 'First Accessed Time', 'Last Accessed Time'])
        hr += '[View assets in Chronicle]({})'.format(response.get('uri', [''])[0])
        ec = {
            'Host': host_context,
            **context_data
        }
    else:
        hr = '### Artifact Accessed: {} \n\n'.format(artifact_value)
        hr += 'No Records Found'
    return hr, ec, response


def gcb_ioc_details_command(client_obj, args: Dict[str, str]):
    """
    This method fetches the IoC Details from Backstory using 'listiocdetails' Search API

    :type client_obj: Client
    :param client_obj: The Client object which abstracts the API calls to Backstory.

    :type args: dict
    :param args: the input artifact value, whose details are to be fetched.

    :return: command output (Human Readable, Context Data and Raw Response)
    :rtype: tuple
    """
    artifact_value = args.get('artifact_value', '')
    artifact_type = get_artifact_type(artifact_value)

    request_url = '{}/artifact/listiocdetails?artifact.{}={}'.format(BACKSTORY_API_V1_URL, artifact_type,
                                                                     urllib.parse.quote(artifact_value))
    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    hr = ''
    if response and response.get('sources'):
        normal_artifact_type = None
        if artifact_type == 'destination_ip_address':
            normal_artifact_type = 'ip'
        elif artifact_type == 'domain_name':
            normal_artifact_type = 'domain'
        else:
            raise ValueError('Unsupported artifact type')

        context_dict = get_context_for_ioc_details(response.get('sources', []), artifact_value, normal_artifact_type,
                                                   is_reputation_command=False)
        ec = {
            outputPaths[normal_artifact_type]: context_dict['standard_context'],
            CHRONICLE_OUTPUT_PATHS['IocDetails']: context_dict['context']
        }

        if context_dict['hr_table_data']:
            hr += tableToMarkdown('IoC Details', context_dict['hr_table_data'],
                                  ['Domain', 'IP Address', 'Category', 'Confidence Score', 'Severity',
                                   'First Accessed Time', 'Last Accessed Time'])
            hr += '[View IoC details in Chronicle]({})'.format(response.get('uri', [''])[0])
        else:
            hr += 'No Records Found'
        return hr, ec, response

    else:
        hr += '### For artifact: {}\n'.format(artifact_value)
        hr += 'No Records Found'

        return hr, ec, response


def ip_command(client_obj, ip_address: str):
    """
    reputation command for given IP address

    :type client_obj: Client
    :param client_obj: object of the client class

    :type ip_address: str
    :param ip_address: contains arguments of reputation command ip

    :return: command output
    :rtype: tuple
    """
    if not is_ip_valid(ip_address, True):
        raise ValueError('Invalid IP - {}'.format(ip_address))

    request_url = '{}/artifact/listiocdetails?artifact.destination_ip_address={}'.format(
        BACKSTORY_API_V1_URL, ip_address)

    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    hr = ''
    if response and response.get('sources'):
        context_dict = get_context_for_ioc_details(response.get('sources', []), ip_address, 'ip')

        # preparing human readable
        hr += 'IP: ' + str(ip_address) + ' found with Reputation: ' + str(context_dict['reputation']) + '\n'
        if context_dict['hr_table_data']:
            hr += tableToMarkdown('Reputation Parameters', context_dict['hr_table_data'],
                                  ['Domain', 'IP Address', 'Category', 'Confidence Score', 'Severity',
                                   'First Accessed Time', 'Last Accessed Time'])
            hr += '[View IoC details in Chronicle]({})'.format(response.get('uri', [''])[0])
        else:
            hr += 'No Records Found'

        # preparing entry context
        ec = {
            'DBotScore': context_dict['dbot_context'],
            outputPaths['ip']: context_dict['standard_context'],
            CHRONICLE_OUTPUT_PATHS['Ip']: context_dict['context']
        }
    else:
        dbot_context = {
            'Indicator': ip_address,
            'Type': 'ip',
            'Vendor': 'Google Chronicle Backstory',
            'Score': 0
        }

        hr += '### IP: {} found with Reputation: Unknown\n'.format(ip_address)
        hr += 'No Records Found'

        ec = {
            'DBotScore': dbot_context
        }

    return hr, ec, response


def domain_command(client_obj, domain_name: str):
    """
    reputation command for given Domain address

    :type client_obj: Client
    :param client_obj: object of the client class

    :type domain_name: str
    :param domain_name: contains arguments of reputation command domain

    :return: command output
    :rtype: tuple
    """
    request_url = '{}/artifact/listiocdetails?artifact.domain_name={}'.format(BACKSTORY_API_V1_URL,
                                                                              urllib.parse.quote(domain_name))
    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    hr = ''
    if response and response.get('sources'):
        context_dict = get_context_for_ioc_details(response.get('sources', []), domain_name, 'domain')

        # preparing human readable
        hr += 'Domain: ' + str(domain_name) + ' found with Reputation: ' + str(context_dict['reputation']) + '\n'
        if context_dict['hr_table_data']:
            hr += tableToMarkdown('Reputation Parameters', context_dict['hr_table_data'],
                                  ['Domain', 'IP Address', 'Category', 'Confidence Score', 'Severity',
                                   'First Accessed Time', 'Last Accessed Time'])
            hr += '[View IoC details in Chronicle]({})'.format(response.get('uri', [''])[0])
        else:
            hr += 'No Records Found'

        # preparing entry context
        ec = {
            'DBotScore': context_dict['dbot_context'],
            outputPaths['domain']: context_dict['standard_context'],
            CHRONICLE_OUTPUT_PATHS['Domain']: context_dict['context']
        }

        return hr, ec, response

    else:
        dbot_context = {
            'Indicator': domain_name,
            'Type': 'domain',
            'Vendor': 'Google Chronicle Backstory',
            'Score': 0
        }

        hr += '### Domain: {} found with Reputation: Unknown\n'.format(domain_name)
        hr += 'No Records Found'

        ec = {
            'DBotScore': dbot_context
        }

        return hr, ec, response


def fetch_incidents(client_obj, params: Dict[str, Any]):
    """
    fetches alerts or IoC domain matches and convert them into actionable incidents.
    :param client_obj:
    :param params:
    :return:
    """
    first_fetch_in_days = params.get('first_fetch_time_interval_days', '3 days').lower()  # 3 days as default
    fetch_limit = params.get('fetch_limit', 10)  # default page size
    filter_severity = params.get('incident_severity', 'ALL')  # All to get all type of severity

    # getting numeric value from string representation
    start_time, end_time = parse_date_range(first_fetch_in_days, date_format=DATE_FORMAT)

    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time', start_time)

    # backstory_alert_type will create actionable incidents based on input selection in configuration
    backstory_alert_type = params.get('backstory_alert_type', 'ioc domain matches')

    incidents = []
    if 'ioc domain matches' != backstory_alert_type.lower():
        events = get_gcb_alerts(client_obj, start_time, end_time, fetch_limit, filter_severity)

        _, contexts = group_infos_by_alert_asset_name(events)

        # Converts event alerts into  actionable incidents
        for event in list(contexts.values()):
            severity = SEVERITY_MAP.get(event['Severities'].lower(), 0)
            incident = {
                'name': '{} for {}'.format(event['AlertName'], event['Asset']),
                'details': json.dumps(event),
                'severity': severity,
                'rawJSON': json.dumps(event)
            }
            incidents.append(incident)
    else:
        events = get_ioc_domain_matches(client_obj, start_time, fetch_limit)
        # Converts IoCs into actionable incidents
        for event in events:
            incident = {
                'name': 'IOC Domain Match: {}'.format(event['Artifact']),
                'details': json.dumps(event),
                'rawJSON': json.dumps(event)
            }
            incidents.append(incident)

    # Saving last_run
    demisto.setLastRun({
        'start_time': end_time
    })

    # this command will create incidents in Demisto
    demisto.incidents(incidents)


def gcb_list_alerts_command(client_obj, args: Dict[str, Any]):
    """
    This method fetches alerts that are correlated to the asset under investigation.
    :type client_obj: Client
    :param client_obj:

    :type args: Dict
    :param args: inputs to fetch alerts from a specified date range. start_time, end_time, and page_size are
        considered for pulling the data.
    """
    start_time, end_time, page_size = get_default_command_args_value(args)

    severity_filter = args.get('severity', 'ALL')

    # gathering all the alerts from Backstory
    alerts = get_gcb_alerts(client_obj, start_time, end_time, page_size, severity_filter)
    if not alerts:
        hr = '### Security Alert(s):'
        hr += 'No Records Found'
        return hr, {}, {}

    # prepare alerts into human readable
    hr = convert_alerts_into_hr(alerts)

    # Remove Url key in context data
    for alert in alerts:
        for alert_info in alert.get('AlertInfo', []):
            if 'Uri' in alert_info.keys():
                del alert_info['Uri']
    ec = {
        CHRONICLE_OUTPUT_PATHS['Alert']: alerts
    }

    return hr, ec, alerts


def gcb_list_events_command(client_obj, args: Dict[str, str]):
    """
    List all of the events discovered within your enterprise on a particular device within the specified time range.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args:  Dict[str, str]
    :param args: it contain arguments of gcb-list-ioc command

    :return: command output
    :rtype: str, dict, dict
    """

    asset_identifier_type = ASSET_IDENTIFIER_NAME_DICT.get(args.get('asset_identifier_type', '').lower(),
                                                           args.get('asset_identifier_type', ''))
    asset_identifier = urllib.parse.quote(args.get('asset_identifier', ''))

    # retrieve arguments and validate it
    start_time, end_time, _ = get_default_command_args_value(args, '2 hours')

    page_size = args.get('page_size', '100')

    # validate page size argument
    if int(page_size) > 1000:
        return_error('Page size should be in the range from 1 to 1000.')

    reference_time = args.get('reference_time', start_time)

    # Make a request URL
    request_url = '{}/asset/listevents?asset.{}={}&start_time={}&end_time={}&page_size={}&reference_time={}' \
        .format(BACKSTORY_API_V1_URL, asset_identifier_type, asset_identifier, start_time, end_time, page_size,
                reference_time)
    demisto.debug('Requested url : ' + request_url)

    # get list of events from Chronicle Backstory
    json_data = validate_response(client_obj, request_url)

    events = json_data.get('events', [])
    if not events:
        hr = 'No Events Found'
        return hr, {}, {}

    # prepare alerts into human readable
    hr = get_list_events_hr(events)
    hr += '[View events in Chronicle]({})'.format(json_data.get('uri', [''])[0])

    if json_data.get('moreDataAvailable', False):
        last_event_timestamp = datetime.strptime(events[-1].get('metadata', {}).get('eventTimestamp', ''), DATE_FORMAT)
        hr += '\n\nMaximum number of events specified in page_size has been returned. There might still be more ' \
              'events in your Chronicle account. To fetch the next set of events, execute the command with the start ' \
              'time as {}'.format(last_event_timestamp.strftime(DATE_FORMAT))

    parsed_ec = get_context_for_events(json_data.get('events', []))

    ec = {
        CHRONICLE_OUTPUT_PATHS["Events"]: parsed_ec
    }

    return hr, ec, json_data


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # supported command list
    chronicle_commands = {
        'gcb-list-iocs': gcb_list_iocs_command,
        'gcb-assets': gcb_assets_command,
        'gcb-ioc-details': gcb_ioc_details_command,
        'gcb-list-alerts': gcb_list_alerts_command,
        'gcb-list-events': gcb_list_events_command
    }
    # initialize configuration parameter
    proxy = demisto.params().get('proxy')
    disable_ssl = demisto.params().get('insecure', False)
    command = demisto.command()

    try:
        validate_configuration_parameters(demisto.params())

        # Initializing client Object
        client_obj = Client(demisto.params(), proxy, disable_ssl)

        # trigger command based on input
        if command == 'test-module':
            test_function(client_obj, demisto.args())
        elif command == 'fetch-incidents':
            fetch_incidents(client_obj, demisto.params())
        elif command == 'ip':
            ip = demisto.args()['ip']
            reputation_operation_command(client_obj, ip, ip_command)
        elif command == 'domain':
            domain = demisto.args()['domain']
            reputation_operation_command(client_obj, domain, domain_command)
        elif command in chronicle_commands:
            return_outputs(*chronicle_commands[command](client_obj, demisto.args()))

    except Exception as e:
        return_error('Failed to execute {} command.\nError: {}'.format(demisto.command(), str(e)))


# initial flow of execution
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
