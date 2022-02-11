from CommonServerPython import *

''' IMPORTS '''
from collections import defaultdict
from typing import Any, Dict, Tuple, List
import httplib2
import urllib.parse
from oauth2client import service_account
from copy import deepcopy
import dateparser
from hashlib import sha256

# A request will be tried 3 times if it fails at the socket/connection level
httplib2.RETRIES = 3

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']

BACKSTORY_API_V1_URL = 'https://{}backstory.googleapis.com/v1'
BACKSTORY_API_V2_URL = 'https://{}backstory.googleapis.com/v2'
MAX_ATTEMPTS = 60

REGIONS = {
    "General": "",
    "Europe": "europe-",
    "Asia": "asia-southeast1-"
}

ISO_DATE_REGEX = (r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):'
                  r'([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?Z$')

CHRONICLE_OUTPUT_PATHS = {
    'Asset': 'GoogleChronicleBackstory.Asset(val.{0} && val.{0} == obj.{0})',
    'Iocs': 'GoogleChronicleBackstory.Iocs(val.Artifact && val.Artifact == obj.Artifact)',
    'IocDetails': 'GoogleChronicleBackstory.IocDetails(val.IoCQueried && val.IoCQueried == obj.IoCQueried)',
    'Ip': 'GoogleChronicleBackstory.IP(val.IoCQueried && val.IoCQueried == obj.IoCQueried)',
    'Domain': 'GoogleChronicleBackstory.Domain(val.IoCQueried && val.IoCQueried == obj.IoCQueried)',
    'Alert': 'GoogleChronicleBackstory.Alert(val.AssetName && val.AssetName == obj.AssetName)',
    'UserAlert': 'GoogleChronicleBackstory.UserAlert(val.User && val.User == obj.User)',
    'Events': 'GoogleChronicleBackstory.Events',
    'Detections': 'GoogleChronicleBackstory.Detections(val.id == obj.id && val.ruleVersion == obj.ruleVersion)',
    'Rules': 'GoogleChronicleBackstory.Rules(val.ruleId == obj.ruleId)',
    'Token': 'GoogleChronicleBackstory.Token(val.name == obj.name)'
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
        self.region = params.get("region") if params.get("region") else "General"


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
    demisto.info('[CHRONICLE DETECTIONS]: Request URL: ' + url.format(REGIONS[client.region]))
    raw_response = client.http_client.request(url.format(REGIONS[client.region]), method)
    if not raw_response:
        raise ValueError('Technical Error while making API call to Chronicle. Empty response received')
    if raw_response[0].status == 500:
        raise ValueError('Internal server error occurred, Reattempt will be initiated.')
    if raw_response[0].status == 429:
        raise ValueError('API rate limit exceeded. Reattempt will be initiated.')
    if raw_response[0].status == 400 or raw_response[0].status == 404:
        raise ValueError(
            'Status code: {}\nError: {}'.format(raw_response[0].status, parse_error_message(raw_response[1])))
    if raw_response[0].status != 200:
        return_error(
            'Status code: {}\nError: {}'.format(raw_response[0].status, parse_error_message(raw_response[1])))
    try:
        response = json.loads(raw_response[1])
        return response
    except json.decoder.JSONDecodeError:
        raise ValueError('Invalid response format while making API call to Chronicle. Response not in JSON format')


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
    fetch_days = param.get('first_fetch', '3 days').lower()
    page_size = param.get('max_fetch', '10')
    time_window = param.get('time_window', '15')

    detection_by_ids = param.get('fetch_detection_by_ids') or ""
    detection_by_id = [r_v_id.strip() for r_v_id in detection_by_ids.split(',')]

    if param.get('backstory_alert_type', 'ioc domain matches').lower() == 'detection alerts' and not \
            param.get('fetch_all_live_detections', False) and not get_unique_value_from_list(detection_by_id):
        raise ValueError('Please enter one or more Rule ID(s) or Version ID(s) as value of "Detections to '
                         'fetch by Rule ID or Version ID" or check the checkbox "Fetch all live rules '
                         'detections" to fetch detections.')

    try:
        # validate service_account_credential configuration parameter
        json.loads(service_account_json, strict=False)

        # validate max_fetch configuration parameter
        if not page_size.isdigit():
            raise ValueError('Incidents fetch limit must be a number')

        invalid_time_window_error_message = 'Time window(in minutes) should be in the numeric range from 1 to 60.'
        if not time_window:
            time_window = '15'
        if not time_window.isdigit():
            raise ValueError(invalid_time_window_error_message)
        time_window = int(time_window)
        if time_window > 60:
            raise ValueError(invalid_time_window_error_message)

        # validate first_fetch parameter
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
    :rtype: str, str, Optional[str]
    """
    if start_date.isdigit():
        raise ValueError("Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z")

    # checking date format
    start_date = dateparser.parse(start_date, settings={'STRICT_PARSING': True})
    if not start_date:
        raise ValueError('Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z')

    start_date = str(datetime.strftime(start_date, DATE_FORMAT))

    if end_date:
        if end_date.isdigit():
            raise ValueError("Invalid end time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z")
        # checking date format
        end_date = dateparser.parse(end_date, settings={'STRICT_PARSING': True})
        if not end_date:
            raise ValueError('Invalid end time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z')

        end_date = str(datetime.strftime(end_date, DATE_FORMAT))

    if reference_time:
        # checking date format
        reference_time = dateparser.parse(reference_time, settings={'STRICT_PARSING': True})
        if not reference_time:
            raise ValueError('Invalid reference time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z')

        reference_time = str(datetime.strftime(reference_time, DATE_FORMAT))

    return start_date, end_date, reference_time


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
    reference_time = None
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
        start_time, end_time, reference_time = validate_start_end_date(start_time, end_time,
                                                                       args.get('reference_time', ''))
    else:
        start_time, end_time, _ = validate_start_end_date(start_time, end_time)

    return start_time, end_time, page_size, reference_time


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


def get_ioc_domain_matches(client_obj, start_time, max_fetch):
    """
    Calls list IOC API with :start_time, :end_time and :max_fetch.
        filter_severity to filter out an alert after getting a response from API. Passing ALL will not filter any data
    :param client_obj perform API request
    :param start_time
    :param max_fetch

    return events - list of dict representing events
    """

    request_url = '{}/ioc/listiocs?start_time={}&page_size={}'.format(BACKSTORY_API_V1_URL, start_time, max_fetch)

    response_body = validate_response(client_obj, request_url)
    ioc_matches = response_body.get('response', {}).get('matches', [])
    parsed_ioc = parse_list_ioc_response(ioc_matches)
    return parsed_ioc['context']


def get_gcb_alerts(client_obj, start_time, end_time, max_fetch, filter_severity):
    """
    Calls list alert API with :start_time, :end_time and :max_fetch.
        filter_severity to filter out an alert after getting a response from API. Passing ALL will not filter any data
    :param client_obj perform API request
    :param start_time
    :param end_time
    :param max_fetch
    :param filter_severity

    return events - list of dict representing events
    """
    request_url = '{}/alert/listalerts?start_time={}&end_time={}&page_size={}'.format(BACKSTORY_API_V1_URL, start_time,
                                                                                      end_time, max_fetch)
    demisto.debug("[CHRONICLE] Request URL for fetching alerts: {}".format(request_url))

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


def validate_and_parse_detection_start_end_time(args: Dict[str, Any]) -> Tuple[str, str]:
    """
    Returns and validates detection_start_time and detection_end_time as per Chronicle Backstory or
     raises a ValueError if the given inputs are invalid.

    :type args: dict
    :param args: contains all arguments for command

    :return : detection_start_time, detection_end_time: Detection start and end time in the format API accepts
    :rtype : Tuple[str, str]
    """
    detection_start_time = args.get('start_time') if args.get('start_time') else args.get('detection_start_time')
    detection_end_time = args.get('end_time') if args.get('end_time') else args.get('detection_end_time')

    list_basis = args.get('list_basis', '')
    if list_basis and not detection_start_time and not detection_end_time:
        raise ValueError("To sort detections by \"list_basis\", either \"start_time\" or \"end_time\" argument is "
                         "required.")

    invalid_time_error_message = 'Invalid {} time. Some supported formats are ISO date format and relative time.' \
                                 ' e.g. 2019-10-17T00:00:00Z, 3 days'
    if detection_start_time:
        if detection_start_time.isdigit():
            raise ValueError(invalid_time_error_message.format('start'))
        detection_start_time = dateparser.parse(detection_start_time, settings={'STRICT_PARSING': True})

        if not detection_start_time:
            raise ValueError(invalid_time_error_message.format('start'))

        detection_start_time = str(datetime.strftime(detection_start_time, DATE_FORMAT))

    if detection_end_time:
        if detection_end_time.isdigit():
            raise ValueError(invalid_time_error_message.format('end'))

        detection_end_time = dateparser.parse(detection_end_time, settings={'STRICT_PARSING': True})
        if not detection_end_time:
            raise ValueError(invalid_time_error_message.format('end'))

        detection_end_time = str(datetime.strftime(detection_end_time, DATE_FORMAT))

    return detection_start_time, detection_end_time


def validate_and_parse_list_detections_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and returns page_size, detection_start_time and detection_end_time.

    :type args: Dict[str, Any]
    :param args: contains all arguments for list-detections command

    :return: Dictionary containing values of page_size, detection_start_time and detection_end_time
     or raise ValueError if the arguments are invalid
    :rtype: Dict[str, Any]
    """

    page_size = args.get('page_size', 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError('Page size should be in the range from 1 to 1000.')

    rule_id = args.get('id', '')
    detection_for_all_versions = argToBoolean(args.get('detection_for_all_versions', False))
    if detection_for_all_versions and not rule_id:
        raise ValueError('If "detection_for_all_versions" is true, rule id is required.')

    detection_start_time, detection_end_time = validate_and_parse_detection_start_end_time(args)

    valid_args = {'page_size': page_size, 'detection_start_time': detection_start_time,
                  'detection_end_time': detection_end_time, 'detection_for_all_versions': detection_for_all_versions}

    return valid_args


def get_hr_for_event_in_detection(event: Dict[str, Any]) -> str:
    """
    Returns a string containing event information for an event

    :param event: event for which hr is to be prepared
    :return: event information in human readable format
    """
    event_info = []

    # Get queried domain, process command line, file use by process information
    more_info = get_more_information(event)

    event_timestamp = event.get('metadata', {}).get('eventTimestamp', '')
    event_type = event.get('metadata', {}).get('eventType', '')
    principal_asset_identifier = get_asset_identifier_details(event.get('principal', {}))
    target_asset_identifier = get_asset_identifier_details(event.get('target', {}))
    queried_domain = more_info[0][:-1]
    process_command_line = more_info[1]
    file_in_use_by_process = more_info[2]
    if event_timestamp:
        event_info.append('**Event Timestamp:** {}'.format(event_timestamp))
    if event_type:
        event_info.append('**Event Type:** {}'.format(event_type))
    if principal_asset_identifier:
        event_info.append('**Principal Asset Identifier:** {}'.format(principal_asset_identifier))
    if target_asset_identifier:
        event_info.append('**Target Asset Identifier:** {}'.format(target_asset_identifier))
    if queried_domain:
        event_info.append('**Queried Domain:** {}'.format(queried_domain))
    if process_command_line:
        event_info.append('**Process Command Line:** {}'.format(process_command_line))
    if file_in_use_by_process:
        event_info.append('**File In Use By Process:** {}'.format(file_in_use_by_process))
    return '\n'.join(event_info)


def get_events_hr_for_detection(events: List[Dict[str, Any]]) -> str:
    """
    Converts events response related to the specified detection into human readable.

    :param events: list of events
    :type events: list

    :return: returns human readable string for the events related to the specified detection
    :rtype: str
    """
    events_hr = []
    for event in events:
        events_hr.append(get_hr_for_event_in_detection(event))

    return '\n\n'.join(events_hr)


def get_event_list_for_detections_hr(result_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts events response related to the specified detection into list of events for command's human readable.

    :param result_events: List having dictionary containing list of events
    :type result_events: List[Dict[str, Any]]

    :return: returns list of the events related to the specified detection
    :rtype: List[Dict[str,Any]]
    """
    events = []
    if result_events:
        for element in result_events:
            for event in element.get('references', []):
                events.append(event.get('event', {}))
    return events


def get_event_list_for_detections_context(result_events: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Converts events response related to the specified detection into list of events for command's context.

    :param result_events: Dictionary containing list of events
    :type result_events: Dict[str, Any]

    :return: returns list of the events related to the specified detection
    :rtype: List[Dict[str,Any]]
    """
    events = []
    if result_events:
        for event in result_events.get('references', []):
            events.append(event.get('event', {}))
    return events


def get_list_detections_hr(detections: List[Dict[str, Any]], rule_or_version_id: str) -> str:
    """
    Converts detections response into human readable.

    :param detections: list of detections
    :type detections: list

    :type rule_or_version_id: str
    :param rule_or_version_id: rule_id or version_id to fetch the detections for.

    :return: returns human readable string for gcb-list-detections command
    :rtype: str
    """

    hr_dict = []
    for detection in detections:
        events = get_event_list_for_detections_hr(detection.get('collectionElements', []))
        detection_details = detection.get('detection', {})
        hr_dict.append({
            'Detection ID': "[{}]({})".format(detection.get('id', ''),
                                              detection_details[0].get('urlBackToProduct', '')),
            'Detection Type': detection.get('type', ''),
            'Detection Time': detection.get('detectionTime', ''),
            'Events': get_events_hr_for_detection(events),
            'Alert State': detection_details[0].get('alertState', '')
        })
    rule_uri = detections[0].get('detection', {})[0].get('urlBackToProduct', '')
    if rule_uri:
        rule_uri = rule_uri.split('&', maxsplit=2)
        rule_uri = '{}&{}'.format(rule_uri[0], rule_uri[1])
    if rule_or_version_id:
        hr_title = 'Detection(s) Details For Rule: [{}]({})'.\
            format(detections[0].get('detection', {})[0].get('ruleName', ''), rule_uri)
    else:
        hr_title = 'Detection(s)'
    hr = tableToMarkdown(hr_title, hr_dict, ['Detection ID', 'Detection Type', 'Detection Time', 'Events',
                                             'Alert State'], removeNull=True)
    return hr


def get_events_context_for_detections(result_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert events in response into Context data for events associated with a detection

    :param result_events: List of Dictionary containing list of events
    :type result_events: List[Dict[str, Any]]

    :return: list of events to populate in the context
    :rtype: List[Dict[str, Any]]
    """
    events_ec = []
    for collection_element in result_events:
        reference = []
        events = get_event_list_for_detections_context(collection_element)
        for event in events:
            event_dict = {}
            if 'metadata' in event.keys():
                event_dict.update(event.pop('metadata'))
            principal_asset_identifier = get_asset_identifier_details(event.get('principal', {}))
            target_asset_identifier = get_asset_identifier_details(event.get('target', {}))
            if principal_asset_identifier:
                event_dict.update({'principalAssetIdentifier': principal_asset_identifier})
            if target_asset_identifier:
                event_dict.update({'targetAssetIdentifier': target_asset_identifier})
            event_dict.update(event)
            reference.append(event_dict)
        collection_element_dict = {'references': reference, 'label': collection_element.get('label', '')}
        events_ec.append(collection_element_dict)

    return events_ec


def get_context_for_detections(detection_resp: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """
    Convert detections response into Context data

    :param detection_resp: Response fetched from the API call for detections
    :type detection_resp: Dict[str, Any]

    :return: list of detections and token to populate context data
    :rtype: Tuple[List[Dict[str, Any]], Dict[str, str]]
    """
    detections_ec = []
    token_ec = {}
    next_page_token = detection_resp.get('nextPageToken')
    if next_page_token:
        token_ec = {'name': 'gcb-list-detections', 'nextPageToken': next_page_token}
    detections = detection_resp.get('detections', [])
    for detection in detections:
        detection_dict = detection
        result_events = detection.get('collectionElements', [])
        if result_events:
            detection_dict['collectionElements'] = get_events_context_for_detections(result_events)

        detection_details = detection.get('detection', {})
        if detection_details:
            detection_dict.update(detection_details[0])
            detection_dict.pop('detection')

        time_window_details = detection.get('timeWindow', {})
        if time_window_details:
            detection_dict.update({'timeWindowStartTime': time_window_details.get('startTime'),
                                   'timeWindowEndTime': time_window_details.get('endTime')})
            detection_dict.pop('timeWindow')
        detections_ec.append(detection_dict)

    return detections_ec, token_ec


def get_detections(client_obj, rule_or_version_id: str, page_size: str, detection_start_time: str,
                   detection_end_time: str, page_token: str, alert_state: str, detection_for_all_versions: bool = False,
                   list_basis: str = None) \
        -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Returns context data and raw response for gcb-list-detections command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api
    :type rule_or_version_id: str
    :param rule_or_version_id: rule_id or version_id to fetch the detections for.
    :type page_size: str
    :param page_size: Number of detections to fetch at a time.
    :type detection_start_time: str
    :param detection_start_time: The time to start listing detections from.
    :type detection_end_time: str
    :param detection_end_time: The time to start listing detections to.
    :type page_token: str
    :param page_token: The token for the page from which the detections should be fetched.
    :type alert_state: str
    :param alert_state: Alert state for the detections to fetch.
    :type detection_for_all_versions: bool
    :param detection_for_all_versions: Whether to retrieve detections for all versions of a rule with a given rule
    identifier.
    :type list_basis: str
    :param list_basis: To sort the detections.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the fetched detections
    """
    # Make a request URL
    if not rule_or_version_id:
        rule_or_version_id = "-"
    if detection_for_all_versions and rule_or_version_id:
        rule_or_version_id = f"{rule_or_version_id}@-"

    request_url = '{}/detect/rules/{}/detections?pageSize={}' \
        .format(BACKSTORY_API_V2_URL, rule_or_version_id, page_size)

    # Append parameters if specified
    if detection_start_time:
        request_url += '&startTime={}'.format(detection_start_time)

    if detection_end_time:
        request_url += '&endTime={}'.format(detection_end_time)

    if alert_state:
        request_url += '&alertState={}'.format(alert_state)

    if list_basis:
        request_url += '&listBasis={}'.format(list_basis)

    if page_token:
        request_url += '&page_token={}'.format(page_token)
    # get list of detections from Chronicle Backstory
    json_data = validate_response(client_obj, request_url)
    raw_resp = deepcopy(json_data)
    parsed_ec, token_ec = get_context_for_detections(json_data)
    ec: Dict[str, Any] = {
        CHRONICLE_OUTPUT_PATHS['Detections']: parsed_ec
    }
    if token_ec:
        ec.update({CHRONICLE_OUTPUT_PATHS['Token']: token_ec})
    return ec, raw_resp


def list_all_rules(client_obj, page_size: str = '100', page_token: str = None) -> Dict[str, Any]:
    """
    Returns all the rules by making the API call according to the passed parameters.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api
    :type page_size: str
    :param page_size: Number of rules to fetch at a time
    :type page_token: str
    :param page_token: The token for the page from which the rules should be fetched

    :rtype: raw_resp: Dict[str, Any]
    :return: raw_resp: Response received by making the API call
    """
    request_url = '{}/detect/rules?pageSize={}'.format(BACKSTORY_API_V2_URL, page_size)

    # Append parameters if specified
    if page_token:
        request_url += '&page_token={}'.format(page_token)

    # get list of rules from Chronicle Backstory
    raw_resp = validate_response(client_obj, request_url)
    return raw_resp


def get_all_live_rules(client_obj, max_live_rules: int = 50) -> List[str]:
    """
    Returns a list of rule_ids containing max_live_rules number of live rules from the list of all the rules.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api
    :type max_live_rules: int
    :param max_live_rules: Maximum number of live rules to be fetched

    :rtype: max_live_rule_ids: List[str]
    :return: max_live_rule_ids: List of live rule_ids
    """
    all_rules_info = list_all_rules(client_obj, '1000')
    all_live_rule_ids = [rule.get('ruleId') for rule in all_rules_info.get('rules', []) if rule.get('liveRuleEnabled')]
    max_live_rule_ids = all_live_rule_ids[:max_live_rules]
    return max_live_rule_ids


def generate_delayed_start_time(time_window: str, start_time: str) -> str:
    """
    Generates the delayed start time according after validating the time window provided by user.

    :type time_window: str
    :param time_window: Time window to delay the start time.
    :type start_time: str
    :param start_time: Initial start time calculated by fetch_incidents method

    :rtype: delayed_start_time: str
    :return: delayed_start_time: Returns generated delayed start time or raises error if invalid value
     is provided for time window configuration parameter
    """
    if not time_window:
        time_window = '15'
    delayed_start_time = dateparser.parse(start_time, settings={'STRICT_PARSING': True})
    delayed_start_time = delayed_start_time - timedelta(minutes=int(time_window))
    delayed_start_time = datetime.strftime(delayed_start_time, DATE_FORMAT)

    return delayed_start_time


def deduplicate_events_and_create_incidents(contexts: List, event_identifiers: List[str], user_alert: bool = False):
    """
    De-duplicates the fetched events and creates a list of actionable incidents.

    :type contexts: List
    :param contexts: Context of the events fetched.
    :type event_identifiers: List[str]
    :param event_identifiers: List of hashes generated for the events fetched in previous call.
    :type user_alert: bool
    :param user_alert: if enable creates user alerts incidents otherwise create asset alerts incidents

    :rtype: new_event_hashes, incidents
    :return: Returns updated list of event hashes and unique incidents that should be created.
    """
    incidents: List[Dict[str, Any]] = []
    new_event_hashes = []
    for event in contexts:
        try:
            event_hash = sha256(str(event).encode()).hexdigest()  # NOSONAR
            new_event_hashes.append(event_hash)
        except Exception as e:
            demisto.error("[CHRONICLE] Skipping insertion of current event since error occurred while calculating"
                          " Hash for the event {}. Error: {}".format(event, str(e)))
            continue
        if event_identifiers and event_hash in event_identifiers:
            demisto.info("[CHRONICLE] Skipping insertion of current event since it already exists."
                         " Event: {}".format(event))
            continue
        if user_alert:
            event["IncidentType"] = "UserAlert"
            incidents.append({
                'name': '{} for {}'.format(event['AlertName'], event['User']),
                'details': json.dumps(event),
                'rawJSON': json.dumps(event)
            })
        else:
            severity = SEVERITY_MAP.get(event['Severities'].lower(), 0)
            event["IncidentType"] = "AssetAlert"
            unique_incident = {
                'name': '{} for {}'.format(event['AlertName'], event['Asset']),
                'details': json.dumps(event),
                'severity': severity,
                'rawJSON': json.dumps(event)
            }
            incidents.append(unique_incident)
    return new_event_hashes, incidents


def deduplicate_detections(detection_context: List[Dict[str, Any]], detection_identifiers: List[Dict[str, Any]]):
    """
    De-duplicates the fetched detections and creates a list of unique detections to be created.

    :type detection_context: Dict[str, Any]
    :param detection_context: Raw response of the detections fetched.
    :type detection_identifiers: List[str]
    :param detection_identifiers: List of dictionaries containing id and ruleVersion of detections.

    :rtype: new_detection_identifiers, incidents
    :return: Returns updated list of detection identifiers and unique incidents that should be created.
    """
    unique_detections = []
    new_detection_identifiers = []
    for detection in detection_context:
        current_detection_identifier = {'id': detection.get('id', ''),
                                        'ruleVersion': detection.get('detection', [])[0].get('ruleVersion', '')}
        new_detection_identifiers.append(current_detection_identifier)
        if detection_identifiers and current_detection_identifier in detection_identifiers:
            demisto.info("[CHRONICLE] Skipping insertion of current detection since it already exists."
                         " Detection: {}".format(detection))
            continue
        unique_detections.append(detection)
    return new_detection_identifiers, unique_detections


def convert_events_to_actionable_incidents(events: list) -> list:
    """
    Convert event to incident.

    :type events: List
    :param events: List of events

    :rtype: list
    :return: Returns updated list of detection identifiers and unique incidents that should be created.
    """
    incidents = []
    for event in events:
        event["IncidentType"] = "DetectionAlert"
        incident = {
            'name': event['detection'][0]['ruleName'],
            'details': json.dumps(event),
            'rawJSON': json.dumps(event)
        }
        incidents.append(incident)

    return incidents


def fetch_detections(client_obj, start_time, end_time, max_fetch, detection_to_process, detection_to_pull,
                     pending_rule_or_version_id: list, alert_state, simple_backoff_rules, fetch_detection_by_list_basis):
    """
    Fetch detections in given time slot. This method calls the get_max_fetch_detections method.
    If detections are more than max_fetch then it partition it into 2 part, from which
    one part(total detection = max_fetch) will be pushed and another part(detection more than max_fetch) will be
    kept in 'detection_to_process' for next cycle. If all rule_id covers, then it will return empty list.
    """

    if not pending_rule_or_version_id and not detection_to_process and not detection_to_pull and not simple_backoff_rules:
        return [], detection_to_process, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules

    # get detections using API call.
    detection_to_process, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules = get_max_fetch_detections(
        client_obj, start_time, end_time, max_fetch, detection_to_process, detection_to_pull,
        pending_rule_or_version_id, alert_state, simple_backoff_rules, fetch_detection_by_list_basis)

    if len(detection_to_process) > max_fetch:
        events, detection_to_process = detection_to_process[:max_fetch], detection_to_process[max_fetch:]
    else:
        events = detection_to_process
        detection_to_process = []

    return events, detection_to_process, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules


def get_max_fetch_detections(client_obj, start_time, end_time, max_fetch, detection_incidents, detection_to_pull,
                             pending_rule_or_version_id, alert_state, simple_backoff_rules, fetch_detection_by_list_basis):
    """
    Get list of detection using detection_to_pull and pending_rule_or_version_id. If the API responds
    with 429, 500 error then it will retry it for 60 times(each attempt take one minute). If it responds
    with 400 or 404 error, then it will skip that rule_id. In case of an empty response for any next_page_token
    it will skip that rule_id.
    """

    # loop if length of detection is less than max_fetch and if any further rule_id(with or without next_page_token)
    # or any retry attempt remaining
    while len(detection_incidents) < max_fetch and (len(pending_rule_or_version_id) != 0
                                                    or detection_to_pull or simple_backoff_rules):

        next_page_token = ''
        if detection_to_pull:
            rule_id = detection_to_pull.get('rule_id')
            next_page_token = detection_to_pull.get('next_page_token')
        elif simple_backoff_rules:
            rule_id = simple_backoff_rules.get('rule_id')
            next_page_token = simple_backoff_rules.get('next_page_token')
        else:
            rule_id = pending_rule_or_version_id.pop(0)

        try:
            _, raw_resp = get_detections(client_obj, rule_id, max_fetch, start_time, end_time, next_page_token,
                                         alert_state, list_basis=fetch_detection_by_list_basis)
        except ValueError as e:
            if str(e).endswith('Reattempt will be initiated.'):
                attempts = simple_backoff_rules.get('attempts', 0)
                if attempts < MAX_ATTEMPTS:
                    demisto.error(
                        f"[CHRONICLE DETECTIONS] Error while fetching incidents: {str(e)} Attempt no : {attempts + 1} "
                        f"for the rule_id : {rule_id} and next_page_token : {next_page_token}")
                    simple_backoff_rules = {'rule_id': rule_id, 'next_page_token': next_page_token,
                                            'attempts': attempts + 1}
                else:
                    demisto.error(f"[CHRONICLE DETECTIONS] Skipping the rule_id : {rule_id} due to the maximum "
                                  f"number of attempts ({MAX_ATTEMPTS}). You'll experience data loss for the given rule_id. "
                                  f"Switching to next rule id.")
                    simple_backoff_rules = {}
                    detection_to_pull = {}
                break

            if str(e).startswith('Status code: 404') or str(e).startswith('Status code: 400'):
                if str(e).startswith('Status code: 404'):
                    demisto.error(
                        f"[CHRONICLE DETECTIONS] Error while fetching incidents: Rule with ID {rule_id} not found.")
                else:
                    demisto.error(
                        f"[CHRONICLE DETECTIONS] Error while fetching incidents: Rule with ID {rule_id} is invalid.")
                detection_to_pull = {}
                simple_backoff_rules = {}
                break

            demisto.error("Error while fetching incidents: " + str(e))
            if not detection_to_pull:
                pending_rule_or_version_id.insert(0, rule_id)

            break

        if not raw_resp:
            detection_to_pull = {}
            simple_backoff_rules = {}
            continue

        detections: List[Dict[str, Any]] = raw_resp.get('detections', [])

        # Add found detection in incident list.
        add_detections_in_incident_list(detections, detection_incidents)

        if raw_resp.get('nextPageToken'):
            next_page_token = str(raw_resp.get('nextPageToken'))
            detection_to_pull = {'rule_id': rule_id, 'next_page_token': next_page_token}
            simple_backoff_rules = {'rule_id': rule_id, 'next_page_token': next_page_token}

        # when exact size is returned but no next_page_token
        if len(detections) <= max_fetch and not raw_resp.get('nextPageToken'):
            detection_to_pull = {}
            simple_backoff_rules = {}

    return detection_incidents, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules


def add_detections_in_incident_list(detections: List, detection_incidents: List) -> None:
    """
    Add found detection in incident list.

    :type detections: list
    :param detections: list of detection
    :type detection_incidents: list
    :param detection_incidents: list of incidents

    :rtype: None
    """

    if detections and len(detections) > 0:
        for detection in detections:
            events_ec = get_events_context_for_detections(detection.get('collectionElements', []))
            detection['collectionElements'] = events_ec
        detection_incidents.extend(detections)


def get_unique_value_from_list(data: List) -> List:
    """
    Return unique value of list with preserving order.

    :type data: list
    :param data: list of value

    :rtype: list
    :return: list of unique value
    """
    output = []

    for value in data:
        if value and value not in output:
            output.append(value)

    return output


def fetch_incidents_asset_alerts(client_obj, params: Dict[str, Any], start_time, end_time, time_window, max_fetch):
    """Fetch incidents of asset alerts type.

    :type client_obj: Client
    :param client_obj: client object.
    :type params: dict
    :param params: configuration parameter of fetch incidents.
    :type start_time: str
    :param start_time: start time of request.
    :type end_time: str
    :param end_time: end time of request.
    :type time_window: str
    :param time_window: time delay for an event to appear in chronicle after generation
    :type max_fetch: str
    :param max_fetch: maximum number of incidents to fetch each time

    :rtype: list
    :return: list of incidents
    """
    assets_alerts_identifiers: List = []
    last_run = demisto.getLastRun()
    filter_severity = params.get('incident_severity', 'ALL')  # All to get all type of severity
    if last_run:
        start_time = last_run.get('start_time') or start_time
        assets_alerts_identifiers = last_run.get('assets_alerts_identifiers', assets_alerts_identifiers)
    delayed_start_time = generate_delayed_start_time(time_window, start_time)
    events = get_gcb_alerts(client_obj, delayed_start_time, end_time, max_fetch, filter_severity)
    _, contexts = group_infos_by_alert_asset_name(events)

    # Converts event alerts into  actionable incidents
    new_event_hashes, incidents = deduplicate_events_and_create_incidents(list(contexts.values()),
                                                                          assets_alerts_identifiers)

    # Updates the event hashes in last run with the new event hashes
    if contexts:
        assets_alerts_identifiers = new_event_hashes

    demisto.setLastRun({
        'start_time': end_time,
        'assets_alerts_identifiers': assets_alerts_identifiers
    })

    return incidents


def fetch_incidents_user_alerts(client_obj, params: Dict[str, Any], start_time, end_time, time_window, max_fetch):
    """Fetch incidents of user alerts type.

    :type client_obj: Client
    :param client_obj: client object.
    :type params: dict
    :param params: configuration parameter of fetch incidents.
    :type start_time: str
    :param start_time: start time of request.
    :type end_time: str
    :param end_time: end time of request.
    :type time_window: str
    :param time_window: time delay for an event to appear in chronicle after generation
    :type max_fetch: str
    :param max_fetch: maximum number of incidents to fetch each time

    :rtype: list
    :return: list of incidents
    """
    user_alerts_identifiers: List = []
    last_run = demisto.getLastRun()

    if last_run:
        start_time = last_run.get('start_time') or start_time
        user_alerts_identifiers = last_run.get('user_alerts_identifiers', user_alerts_identifiers)
    delayed_start_time = generate_delayed_start_time(time_window, start_time)
    events = get_user_alerts(client_obj, delayed_start_time, end_time, max_fetch)
    _, contexts = group_infos_by_alert_user_name(events)

    # Converts user alerts into  actionable incidents
    new_event_hashes, incidents = deduplicate_events_and_create_incidents(contexts, user_alerts_identifiers,
                                                                          user_alert=True)

    # Updates the event hashes in last run with the new event hashes
    if contexts:
        user_alerts_identifiers = new_event_hashes

    demisto.setLastRun({
        'start_time': end_time,
        'user_alerts_identifiers': user_alerts_identifiers
    })

    return incidents


def fetch_incidents_detection_alerts(client_obj, params: Dict[str, Any], start_time, end_time, time_window, max_fetch):
    """Fetch incidents of detection alert type.

    :type client_obj: Client
    :param client_obj: client object.
    :type params: dict
    :param params: configuration parameter of fetch incidents.
    :type start_time: str
    :param start_time: start time of request.
    :type end_time: str
    :param end_time: end time of request.
    :type time_window: str
    :param time_window: time delay for an event to appear in chronicle after generation
    :type max_fetch: str
    :param max_fetch: maximum number of incidents to fetch each time

    :rtype: list
    :return: list of incidents
    """

    # list of detections that were pulled but not processed due to max_fetch.
    detection_to_process: List[Dict[str, Any]] = []
    # detections that are larger than max_fetch and had a next page token for fetch incident.
    detection_to_pull: Dict[str, Any] = {}
    # max_attempts track for 429 and 500 error
    simple_backoff_rules: Dict[str, Any] = {}
    # rule_id or version_id and alert_state for which detections are yet to be fetched.
    pending_rule_or_version_id_with_alert_state: Dict[str, Any] = {}
    detection_identifiers: List = []
    rule_first_fetched_time = None

    last_run = demisto.getLastRun()
    incidents = []

    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time') or start_time
        detection_identifiers = last_run.get('detection_identifiers', detection_identifiers)
        detection_to_process = last_run.get('detection_to_process', detection_to_process)
        detection_to_pull = last_run.get('detection_to_pull', detection_to_pull)
        simple_backoff_rules = last_run.get('simple_backoff_rules', simple_backoff_rules)
        pending_rule_or_version_id_with_alert_state = last_run.get('pending_rule_or_version_id_with_alert_state',
                                                                   pending_rule_or_version_id_with_alert_state)

        end_time = last_run.get('rule_first_fetched_time') or end_time
    if not last_run.get('rule_first_fetched_time'):
        demisto.info(f"Starting new time window from START-TIME :  {start_time} to END_TIME : {end_time}")

    delayed_start_time = generate_delayed_start_time(time_window, start_time)
    fetch_detection_by_alert_state = pending_rule_or_version_id_with_alert_state.get('alert_state', '')
    fetch_detection_by_list_basis = pending_rule_or_version_id_with_alert_state.get('listBasis', 'CREATED_TIME')
    # giving priority to comma separated detection ids over check box of fetch all live detections
    if not pending_rule_or_version_id_with_alert_state.get("rule_id") and \
            not detection_to_pull and not detection_to_process and not simple_backoff_rules:
        fetch_detection_by_ids = params.get('fetch_detection_by_ids') or ""
        fetch_detection_by_ids = get_unique_value_from_list(
            [r_v_id.strip() for r_v_id in fetch_detection_by_ids.split(',')])

        fetch_detection_by_alert_state = params.get('fetch_detection_by_alert_state',
                                                    fetch_detection_by_alert_state)
        fetch_detection_by_list_basis = params.get('fetch_detection_by_list_basis', fetch_detection_by_list_basis)
        if not fetch_detection_by_ids:
            fetch_detection_by_ids = get_all_live_rules(client_obj, max_live_rules=50)

        fetch_detection_by_ids = get_unique_value_from_list(fetch_detection_by_ids)

        # when 1st time fetch or when pending_rule_or_version_id got emptied in last sync.
        # when detection_to_pull has some rule ids
        pending_rule_or_version_id_with_alert_state.update({'rule_id': fetch_detection_by_ids,
                                                            'alert_state': fetch_detection_by_alert_state,
                                                            'listBasis': fetch_detection_by_list_basis})

    events, detection_to_process, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules \
        = fetch_detections(client_obj, delayed_start_time, end_time, int(max_fetch), detection_to_process,
                           detection_to_pull, pending_rule_or_version_id_with_alert_state.get('rule_id', ''),
                           pending_rule_or_version_id_with_alert_state.get('alert_state', ''), simple_backoff_rules,
                           pending_rule_or_version_id_with_alert_state.get('listBasis'))

    # The batch processing is in progress i.e. detections for pending rules are yet to be fetched
    # so updating the end_time to the start time when considered for current batch
    if pending_rule_or_version_id or detection_to_pull or simple_backoff_rules:
        rule_first_fetched_time = end_time
        end_time = start_time
    else:
        demisto.info(f"End of current time window from START-TIME : {start_time} to END_TIME : {end_time}")

    pending_rule_or_version_id_with_alert_state.update({'rule_id': pending_rule_or_version_id,
                                                        'alert_state': fetch_detection_by_alert_state,
                                                        'listBasis': fetch_detection_by_list_basis})

    detection_identifiers, unique_detections = deduplicate_detections(events, detection_identifiers)

    if unique_detections:
        incidents = convert_events_to_actionable_incidents(unique_detections)

    demisto.setLastRun({
        'start_time': end_time,
        'detection_identifiers': detection_identifiers,
        'rule_first_fetched_time': rule_first_fetched_time,
        'detection_to_process': detection_to_process,
        'detection_to_pull': detection_to_pull,
        'simple_backoff_rules': simple_backoff_rules,
        'pending_rule_or_version_id_with_alert_state': pending_rule_or_version_id_with_alert_state
    })

    return incidents


def convert_events_to_chronicle_event_incident_field(events: List) -> None:
    """Convert Chronicle event into Chronicle Event incident field.

    :type events: list
    :param events: list of Chronicle UDM events

    :rtype: list
    :return: list of incidents
    """
    for event in events:
        event["principalAssetIdentifier"] = get_asset_identifier_details(event.get('principal', {}))
        event["targetAssetIdentifier"] = get_asset_identifier_details(event.get('target', {}))


def get_user_alerts(client_obj, start_time, end_time, max_fetch):
    """
    Get user alerts and parse response.

    :type client_obj: Client
    :param client_obj: client object
    :type start_time: str
    :param start_time: starting time of request
    :type end_time: str
    :param end_time: end time of request
    :type max_fetch: str
    :param max_fetch: number of records will be returned

    :rtype: list
    :return: list of alerts
    """
    request_url = '{}/alert/listalerts?start_time={}&end_time={}&page_size={}'.format(BACKSTORY_API_V1_URL, start_time,
                                                                                      end_time, max_fetch)
    demisto.debug("[CHRONICLE] Request URL for fetching user alerts: {}".format(request_url))

    json_response = validate_response(client_obj, request_url)

    alerts = []
    for user_alert in json_response.get('userAlerts', []):

        # parsing each alert infos
        infos = []
        for alert_info in user_alert['alertInfos']:
            info = {
                'Name': alert_info.get('name', ''),
                'SourceProduct': alert_info.get('sourceProduct', ''),
                'Timestamp': alert_info.get('timestamp', ''),
                'Uri': alert_info.get('uri', [''])[0],
                'RawLog': base64.b64decode(alert_info.get('rawLog', '')).decode(),  # decode base64 raw log
                'UdmEvent': alert_info.get('udmEvent', {})
            }
            infos.append(info)
        user_identifier = list(user_alert.get("user", {}).values())
        asset_alert = {
            'User': user_identifier[0] if user_identifier else "",
            'AlertCounts': len(infos),
            'AlertInfo': infos
        }
        alerts.append(asset_alert)
    return alerts


def group_infos_by_alert_user_name(user_alerts):
    """
    Group user alerts with combination of user identifier and alert name

    :type user_alerts: list
    :param user_alerts: list of user alerts

    :rtype: str, list
    :return: human readable and incident context data
    """
    user_alerts = deepcopy(user_alerts)

    hr = []
    incident_context = []
    unique_alert = defaultdict(list)
    for user_alert in user_alerts:
        user = user_alert.get("User", "")
        for alert_info in user_alert["AlertInfo"]:
            alert_info["User"] = user
            unique_alert[user + " - " + alert_info["Name"]].append(alert_info)

    for _, value in unique_alert.items():
        occurrences = []
        events = []
        raw_logs = []
        for info in value:
            occurrences.append(info.get("Timestamp", ""))
            events.append(info.get("UdmEvent", ""))
            raw_logs.append(info.get("RawLog", ""))
        occurrences.sort()
        events = get_context_for_events(events)
        convert_events_to_chronicle_event_incident_field(events)

        hr.append({
            "User": '[{}]({})'.format(value[0]["User"], value[0]["Uri"]),
            'Alerts': len(value),
            'Alert Names': value[0].get("Name", ""),
            'First Seen': get_informal_time(occurrences[0]),
            'Last Seen': get_informal_time(occurrences[-1]),
            'Sources': value[0].get("SourceProduct", ""),
        })
        incident_context.append({
            "User": value[0]["User"],
            'Alerts': len(value),
            'AlertName': value[0].get("Name", ""),
            'Occurrences': occurrences,
            'FirstSeen': occurrences[0],
            'LastSeen': occurrences[-1],
            'Sources': value[0].get("SourceProduct", ""),
            'UdmEvents': events,
            'RawLogs': raw_logs
        })

    return hr, incident_context


def get_user_alert_hr_and_ec(client_obj: Client, start_time: str, end_time: str, page_size: str):
    """
    Get and parse HR, EC and raw response.

    :type client_obj: Client
    :param client_obj: client object
    :type start_time: str
    :param start_time: start time
    :type end_time: str
    :param end_time: end time
    :type page_size: str
    :param page_size: maximum number of records to be fetch

    :rtype: str, dict, dict
    :return: human readable. entry context and raw response
    """
    alerts = get_user_alerts(client_obj, start_time, end_time, page_size)
    if not alerts:
        hr = '### User Alert(s): '
        hr += 'No Records Found'
        return hr, {}, {}

    # prepare alerts into human readable
    data, _ = group_infos_by_alert_user_name(alerts)
    hr = tableToMarkdown('User Alert(s)', data, ['Alerts', 'User', 'Alert Names', 'First Seen', 'Last Seen', 'Sources'],
                         removeNull=True)

    for alert in alerts:
        for alert_info in alert.get('AlertInfo', []):
            alert_info.pop('Uri', None)
            alert_info.pop('UdmEvent', None)

    ec = {
        CHRONICLE_OUTPUT_PATHS['UserAlert']: alerts
    }

    return hr, ec, alerts


def get_context_for_rules(rule_resp: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """
    Convert rules response into Context data

    :param rule_resp: Response fetched from the API call for rules
    :type rule_resp: Dict[str, Any]

    :return: list of rules and token to populate context data
    :rtype: Tuple[List[Dict[str, Any]], Dict[str, str]]
    """
    rules_ec = []
    token_ec = {}
    next_page_token = rule_resp.get('nextPageToken')
    if next_page_token:
        token_ec = {'name': 'gcb-list-rules', 'nextPageToken': next_page_token}
    rules = rule_resp.get('rules', [])
    for rule in rules:
        rules_ec.append(rule)

    return rules_ec, token_ec


def get_rules(client_obj, args: Dict[str, str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Returns context data and raw response for gcb-list-rules command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args:  Dict[str, str]
    :param args: it contain arguments of gcb-list-rules command

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the fetched rules
    """
    page_size = args.get('page_size', 100)
    validate_page_size(page_size)
    page_token = args.get('page_token', '')
    if int(page_size) > 1000:
        raise ValueError('Page size should be in the range from 1 to 1000.')

    live_rule = args.get('live_rule', '').lower()
    if live_rule and live_rule != 'true' and live_rule != 'false':
        raise ValueError('Live rule should be true or false.')

    request_url = '{}/detect/rules?pageSize={}'.format(BACKSTORY_API_V2_URL, page_size)

    # Append parameters if specified
    if page_token:
        request_url += '&page_token={}'.format(page_token)

    # get list of rules from Chronicle Backstory
    json_data = validate_response(client_obj, request_url)
    if live_rule:
        if live_rule == 'true':
            list_live_rule = [rule for rule in json_data.get('rules', []) if rule.get('liveRuleEnabled')]
        else:
            list_live_rule = [rule for rule in json_data.get('rules', []) if not rule.get('liveRuleEnabled')]
        json_data = {
            'rules': list_live_rule
        }
    raw_resp = deepcopy(json_data)
    parsed_ec, token_ec = get_context_for_rules(json_data)
    ec: Dict[str, Any] = {
        CHRONICLE_OUTPUT_PATHS['Rules']: parsed_ec
    }
    if token_ec:
        ec.update({CHRONICLE_OUTPUT_PATHS['Token']: token_ec})
    return ec, raw_resp


def get_list_rules_hr(rules: List[Dict[str, Any]]) -> str:
    """
    Converts rules response into human readable.

    :param rules: list of rules
    :type rules: list

    :return: returns human readable string for gcb-list-rules command
    :rtype: str
    """
    hr_dict = []
    for rule in rules:
        hr_dict.append({
            'Rule ID': rule.get('ruleId'),
            'Rule Name': rule.get('ruleName'),
            'Compilation State': rule.get('compilationState', '')
        })
    hr = tableToMarkdown('Rule(s) Details', hr_dict, ['Rule ID', 'Rule Name', 'Compilation State'],
                         removeNull=True)
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

    start_time, _, page_size, _ = get_default_command_args_value(args)

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

    start_time, end_time, page_size, _ = get_default_command_args_value(args)

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

    :type client_obj: Client
    :param client_obj: object of the client class

    :type params: dict
    :param params: configuration parameter of fetch incidents
    :return:
    """
    first_fetch_in_days = params.get('first_fetch', '3 days').lower()  # 3 days as default
    max_fetch = params.get('max_fetch', 10)  # default page size
    time_window = params.get('time_window', '15')

    # getting numeric value from string representation
    start_time, end_time = parse_date_range(first_fetch_in_days, date_format=DATE_FORMAT)

    # backstory_alert_type will create actionable incidents based on input selection in configuration
    backstory_alert_type = params.get('backstory_alert_type', 'ioc domain matches').lower()

    incidents = []

    if "assets with alerts" == backstory_alert_type:
        incidents = fetch_incidents_asset_alerts(client_obj, params, start_time, end_time, time_window, max_fetch)
    elif "user alerts" == backstory_alert_type:
        incidents = fetch_incidents_user_alerts(client_obj, params, start_time, end_time, time_window, max_fetch)
    elif 'detection alerts' == backstory_alert_type:
        incidents = fetch_incidents_detection_alerts(client_obj, params, start_time, end_time, time_window, max_fetch)
    else:
        last_run = demisto.getLastRun()
        if last_run:
            start_time = last_run.get('start_time') or start_time

        events = get_ioc_domain_matches(client_obj, start_time, max_fetch)
        # Converts IoCs into actionable incidents
        for event in events:
            event["IncidentType"] = "IocDomainMatches"
            incident = {
                'name': 'IOC Domain Match: {}'.format(event['Artifact']),
                'details': json.dumps(event),
                'rawJSON': json.dumps(event)
            }
            incidents.append(incident)

        demisto.setLastRun({'start_time': end_time})

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
    start_time, end_time, page_size, _ = get_default_command_args_value(args)

    alert_type = args.get('alert_type', 'Asset Alerts').lower()

    if alert_type not in ["asset alerts", "user alerts"]:
        raise ValueError('Allowed value for alert type should be either "Asset Alerts" or "User Alerts".')

    if alert_type == 'asset alerts':
        severity_filter = args.get('severity', 'ALL')

        # gathering all the alerts from Backstory
        alerts = get_gcb_alerts(client_obj, start_time, end_time, page_size, severity_filter)
        if not alerts:
            hr = '### Security Alert(s): '
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
    else:
        hr, ec, raw_alert = get_user_alert_hr_and_ec(client_obj, start_time, end_time, page_size)
        return hr, ec, raw_alert


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
    start_time, end_time, _, _ = get_default_command_args_value(args, '2 hours')

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
        last_event_timestamp = events[-1].get('metadata', {}).get('eventTimestamp', '')
        hr += '\n\nMaximum number of events specified in page_size has been returned. There might' \
              ' still be more events in your Chronicle account.'
        if not dateparser.parse(last_event_timestamp, settings={'STRICT_PARSING': True}):
            demisto.error('Event timestamp of the last event: {} is invalid.'.format(last_event_timestamp))
            hr += ' An error occurred while fetching the start time that could have been used to' \
                  ' fetch next set of events.'
        else:
            hr += ' To fetch the next set of events, execute the command with the start time as {}.' \
                .format(last_event_timestamp)

    parsed_ec = get_context_for_events(json_data.get('events', []))

    ec = {
        CHRONICLE_OUTPUT_PATHS["Events"]: parsed_ec
    }

    return hr, ec, json_data


def gcb_list_detections_command(client_obj, args: Dict[str, str]):
    """
    Return the Detections for a specified Rule Version.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args:  Dict[str, str]
    :param args: it contain arguments of gcb-list-detections command

    :return: command output
    :rtype: str, dict, dict
    """

    # retrieve arguments and validate it
    valid_args = validate_and_parse_list_detections_args(args)

    ec, json_data = get_detections(client_obj, args.get('id', ''), valid_args.get('page_size', ''),
                                   valid_args.get('detection_start_time', ''), valid_args.get('detection_end_time', ''),
                                   args.get('page_token', ''), args.get('alert_state', ''),
                                   valid_args.get('detection_for_all_versions', False),
                                   args.get('list_basis', ''))

    detections = json_data.get('detections', [])
    if not detections:
        hr = 'No Detections Found'
        return hr, {}, {}

    # prepare alerts into human readable
    hr = get_list_detections_hr(detections, args.get('id', ''))
    hr += '\nView all detections for this rule in Chronicle by clicking on {} and to view individual detection' \
          ' in Chronicle click on its respective Detection ID.\n\nNote: If a specific version of the rule is provided' \
          ' then detections for that specific version will be fetched.'.format(detections[0].
                                                                               get('detection')[0].get('ruleName'))

    next_page_token = json_data.get('nextPageToken')
    if next_page_token:
        hr += '\nMaximum number of detections specified in page_size has been returned. To fetch the next set of' \
              ' detections, execute the command with the page token as {}.'.format(next_page_token)

    return hr, ec, json_data


def gcb_list_rules_command(client_obj, args: Dict[str, str]):
    """
    Returns the latest version of all rules.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args:  Dict[str, str]
    :param args: it contain arguments of gcb-list-rules command

    :return: command output
    :rtype: str, dict, dict
    """
    ec, json_data = get_rules(client_obj, args)

    rules = json_data.get('rules', [])
    if not rules:
        hr = 'No Rules Found'
        return hr, {}, {}

    hr = get_list_rules_hr(rules)

    next_page_token = json_data.get('nextPageToken')
    if next_page_token:
        hr += '\nMaximum number of rules specified in page_size has been returned. To fetch the next set of' \
              ' rules, execute the command with the page token as {}.'.format(next_page_token)

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
        'gcb-list-events': gcb_list_events_command,
        'gcb-list-detections': gcb_list_detections_command,
        'gcb-list-rules': gcb_list_rules_command
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
