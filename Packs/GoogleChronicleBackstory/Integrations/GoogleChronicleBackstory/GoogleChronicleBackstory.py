"""Main file for GoogleChronicleBackstory Integration."""
from CommonServerPython import *

from collections import defaultdict
from typing import Any

import urllib.parse
from google.oauth2 import service_account
from google.auth.transport import requests as auth_requests
from copy import deepcopy
import dateparser
from hashlib import sha256
from datetime import datetime

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']
STATUS_LIST_TO_RETRY = [429] + list(range(500, 600))
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5

BACKSTORY_API_V1_URL = 'https://{}backstory.googleapis.com/v1'
BACKSTORY_API_V2_URL = 'https://{}backstory.googleapis.com/v2'
MAX_ATTEMPTS = 60
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_CONTENT_TYPE = 'PLAIN_TEXT'
VALID_CONTENT_TYPE = ['PLAIN_TEXT', 'CIDR', 'REGEX']
REGIONS = {
    "General": "",
    "Europe": "europe-",
    "Asia": "asia-southeast1-",
    "Europe-west2": "europe-west2-"
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
    'Events': 'GoogleChronicleBackstory.Events(val.id == obj.id)',
    'UDMEvents': 'GoogleChronicleBackstory.Events(val.id == obj.id)',
    'Detections': 'GoogleChronicleBackstory.Detections(val.id == obj.id && val.ruleVersion == obj.ruleVersion)',
    'CuratedRuleDetections': 'GoogleChronicleBackstory.CuratedRuleDetections(val.id == obj.id)',
    'Rules': 'GoogleChronicleBackstory.Rules(val.ruleId == obj.ruleId)',
    'Token': 'GoogleChronicleBackstory.Token(val.name == obj.name)',
    'DeleteRule': 'GoogleChronicleBackstory.DeleteRule(val.ruleId == obj.ruleId)',
    'RuleAlertingChange': 'GoogleChronicleBackstory.RuleAlertingChange(val.ruleId == obj.ruleId)',
    'LiveRuleStatusChange': 'GoogleChronicleBackstory.LiveRuleStatusChange(val.ruleId == obj.ruleId)',
    'RetroHunt': 'GoogleChronicleBackstory.RetroHunt(val.retrohuntId == obj.retrohuntId)',
    'ReferenceList': 'GoogleChronicleBackstory.ReferenceList(val.name == obj.name)',
    'VerifyReferenceList': 'GoogleChronicleBackstory.VerifyReferenceList(val.command_name == obj.command_name)',
    'ListReferenceList': 'GoogleChronicleBackstory.ReferenceLists(val.name == obj.name)',
    'StreamRules': 'GoogleChronicleBackstory.StreamRules(val.id == obj.id)',
    'AssetAliases': 'GoogleChronicleBackstory.AssetAliases(val.asset.asset_ip_address == obj.asset.asset_ip_address '
                    '&& val.asset.product_id == obj.asset.product_id && val.asset.mac == obj.asset.mac && '
                    'val.asset.hostname == obj.asset.hostname)',
    'CuratedRules': 'GoogleChronicleBackstory.CuratedRules(val.ruleId == obj.ruleId)',
    'UserAliases': 'GoogleChronicleBackstory.UserAliases(val.user.email == obj.user.email '
                   '&& val.user.username == obj.user.username && val.user.windows_sid == obj.user.windows_sid && '
                   'val.user.employee_id == obj.user.employee_id && val.user.product_object_id == '
                   'obj.user.product_object_id ) ',
    'VerifyValueInReferenceList': 'GoogleChronicleBackstory.VerifyValueInReferenceList(val.value == obj.value && '
                                  'val.case_insensitive == obj.case_insensitive)',
    'VerifyRule': 'GoogleChronicleBackstory.VerifyRule(val.command_name == obj.command_name)',
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

USER_IDENTIFIER_NAME_DICT = {
    "email": "email",
    "username": "username",
    "windows sid": "windows_sid",
    "employee id": "employee_id",
    "product object id": "product_object_id",
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
    'informational': 0.5,
    'low': 1,
    'medium': 2,
    'high': 3
}

MESSAGES = {
    "INVALID_DAY_ARGUMENT": 'Invalid preset time range value provided. Allowed values are "Last 1 day", "Last 7 days", '
                            '"Last 15 days" and "Last 30 days"',
    "INVALID_PAGE_SIZE": 'Page size should be in the range from 1 to {}.',
    "INVALID_LIMIT_RANGE": 'Limit should be in the range from 1 to {}.',
    "INVALID_LIMIT_TYPE": 'Limit must be a non-zero and positive numeric value.',
    "INVALID_MAX_RESULTS": 'Max Results should be in the range 1 to 10000.',
    "NO_RECORDS": 'No Records Found',
    "INVALID_RULE_TEXT": 'Invalid rule text provided. Section "meta", "events" or "condition" is missing.',
    "REQUIRED_ARGUMENT": 'Missing argument {}.',
    "VALIDATE_SINGLE_SELECT": '{} can have one of these values only {}.',
    "CHANGE_RULE_ALERTING_METADATA": 'Alerting status for the rule with ID {} has been successfully {}.',
    "CHANGE_LIVE_RULE_STATUS_METADATA": 'Live rule status for the rule with ID {} has been successfully {}.',
    "CANCEL_RETROHUNT": 'Retrohunt for the rule with ID {} has been successfully cancelled.',
    "INVALID_DATE": 'Invalid {} time, supported formats are: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, '
                    'N hours. E.g. 2022-05-15T12:24:36Z, 2021-18-19, 6 days, 20 hours, 01 Mar 2021,'
                    ' 01 Feb 2021 04:45:33',
    "PROVIDE_CURATED_RULE_ID": 'Please provide at least one curated rule ID in "Detections to fetch by Rule ID or '
                               'Version ID" field to retrieve the Curated Rule Detection alerts.',
    "CURATED_RULE_ID_REQUIRED": 'A Curated Rule ID is required to retrieve the detections.',
    "QUERY_REQUIRED": 'Query is required to retrieve the events.',
    "EMPTY_ASSET_ALIASES": 'No asset aliases found for the provided asset identifier: "{}".',
}
FIRST_ACCESSED_TIME = 'First Accessed Time'
LAST_ACCESSED_TIME = 'Last Accessed Time'
IP_ADDRESS = 'IP Address'
CONFIDENCE_SCORE = 'Confidence Score'
VENDOR = 'Google Chronicle Backstory'
LAST_SEEN_AGO = 'Last Seen Ago'
LAST_SEEN = 'Last Seen'
FIRST_SEEN_AGO = 'First Seen Ago'
FIRST_SEEN = 'First Seen'
ALERT_NAMES = 'Alert Names'
MARKDOWN_CHARS = r"\*_{}[]()#+-!"

''' CLIENT CLASS '''


class Client:
    """
    Client to use in integration to fetch data from Chronicle Backstory.

    requires service_account_credentials : a json formatted string act as a token access
    """

    def __init__(self, params: dict[str, Any], proxy, disable_ssl):
        """
        Initialize HTTP Client.

        :param params: parameter returned from demisto.params()
        :param proxy: whether to use environment proxy
        :param disable_ssl: whether to disable ssl
        """
        encoded_service_account = str(params.get('service_account_credential'))
        service_account_credential = json.loads(encoded_service_account, strict=False)
        # Create a credential using the Google Developer Service Account Credential and Chronicle API scope.
        credentials = service_account.Credentials.from_service_account_info(service_account_credential, scopes=SCOPES)

        proxies = {}
        if proxy:
            proxies = handle_proxy()
            if not proxies.get('https', True):
                raise DemistoException('https proxy value is empty. Check Demisto server configuration' + str(proxies))
            https_proxy = proxies['https']
            if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
                proxies['https'] = 'https://' + https_proxy
        else:
            skip_proxy()

        # Build an HTTP client which can make authorized OAuth requests.
        self.http_client = auth_requests.AuthorizedSession(credentials)
        self.proxy_info = proxies
        self.disable_ssl = disable_ssl

        self._implement_retry(retries=MAX_RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY,
                              backoff_factor=BACKOFF_FACTOR)

        region = params.get('region', '')
        other_region = params.get('other_region', '').strip()
        if region:
            if other_region and other_region[-1] != '-':
                other_region = f'{other_region}-'
            self.region = REGIONS[region] if region.lower() != 'other' else other_region
        else:
            self.region = REGIONS['General']

    def _implement_retry(self, retries=0,
                         status_list_to_retry=None,
                         backoff_factor=5,
                         raise_on_redirect=False,
                         raise_on_status=False):
        """
        Implements the retry mechanism.
        In the default case where retries = 0 the request will fail on the first time.

        :type retries: ``int``
        :param retries: How many retries should be made in case of a failure. when set to '0'- will fail on the first time.

        :type status_list_to_retry: ``iterable``
        :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
            A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
            and the response status code is in ``status_list_to_retry``.

        :type backoff_factor ``float``
        :param backoff_factor:
            A backoff factor to apply between attempts after the second try
            (most errors are resolved immediately by a second try without a
            delay). urllib3 will sleep for::

                {backoff factor} * (2 ** ({number of total retries} - 1))

            seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
            for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
            than :attr:`Retry.BACKOFF_MAX`.

            By default, backoff_factor set to 5

        :type raise_on_redirect ``bool``
        :param raise_on_redirect: Whether, if the number of redirects is
            exhausted, to raise a MaxRetryError, or to return a response with a
            response code in the 3xx range.

        :type raise_on_status ``bool``
        :param raise_on_status: Similar meaning to ``raise_on_redirect``:
            whether we should raise an exception, or return a response,
            if status falls in ``status_forcelist`` range and retries have
            been exhausted.
        """
        try:
            method_whitelist = "allowed_methods" if hasattr(Retry.DEFAULT,  # type: ignore[attr-defined]
                                                            "allowed_methods") else "method_whitelist"
            whitelist_kawargs = {
                method_whitelist: frozenset(['GET', 'POST', 'PUT'])
            }
            retry = Retry(
                total=retries,
                read=retries,
                connect=retries,
                backoff_factor=backoff_factor,
                status=retries,
                status_forcelist=status_list_to_retry,
                raise_on_status=raise_on_status,
                raise_on_redirect=raise_on_redirect,
                **whitelist_kawargs  # type: ignore[arg-type]
            )
            http_adapter = HTTPAdapter(max_retries=retry)

            if not self.disable_ssl:
                https_adapter = http_adapter
            elif IS_PY3 and PY_VER_MINOR >= 10:
                https_adapter = SSLAdapter(max_retries=retry, verify=not self.disable_ssl)  # type: ignore[arg-type]
            else:
                https_adapter = http_adapter

            self.http_client.mount('https://', https_adapter)

        except NameError:
            pass


''' HELPER FUNCTIONS '''


def validate_response(client: Client, url, method='GET', body=None):
    """
    Get response from Chronicle Search API and validate it.

    :param client: object of client class
    :type client: object of client class

    :param url: url
    :type url: str

    :param method: HTTP request method
    :type method: str

    :param body: data to pass with the request
    :type body: str

    :return: response
    """
    demisto.info('[CHRONICLE DETECTIONS]: Request URL: ' + url.format(client.region))
    raw_response = client.http_client.request(url=url.format(client.region), method=method, data=body,
                                              proxies=client.proxy_info, verify=not client.disable_ssl)

    if 500 <= raw_response.status_code <= 599:
        raise ValueError(
            f'Internal server error occurred. Failed to execute request with 3 retries.\n'
            f'Message: {parse_error_message(raw_response.text, client.region)}')
    if raw_response.status_code == 429:
        raise ValueError(
            f'API rate limit exceeded. Failed to execute request with 3 retries.\n'
            f'Message: {parse_error_message(raw_response.text, client.region)}')
    if raw_response.status_code == 400 or raw_response.status_code == 404:
        raise ValueError(
            f'Status code: {raw_response.status_code}\nError: {parse_error_message(raw_response.text, client.region)}')
    if raw_response.status_code != 200:
        raise ValueError(
            f'Status code: {raw_response.status_code}\nError: {parse_error_message(raw_response.text, client.region)}')
    if not raw_response.text:
        raise ValueError('Technical Error while making API call to Chronicle. '
                         f'Empty response received with the status code: {raw_response.status_code}')
    try:
        response = remove_empty_elements(raw_response.json())
        return response
    except json.decoder.JSONDecodeError:
        raise ValueError('Invalid response format while making API call to Chronicle. Response not in JSON format')


def trim_args(args):
    """
    Trim the arguments for extra spaces.

    :type args: Dict
    :param args: it contains arguments of the command
    """
    for key, value in args.items():
        args[key] = value.strip()

    return args


def string_escape_markdown(data: Any):
    """
    Escape any chars that might break a markdown string.
    :param data: The data to be modified (required).
    :return: A modified data.
    """
    if isinstance(data, str):
        data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
    elif isinstance(data, list):
        new_data = []
        for sub_data in data:
            if isinstance(sub_data, str):
                sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
            new_data.append(sub_data)
        data = new_data
    return data


def validate_argument(value, name) -> str:
    """
    Check if empty string is passed as value for argument and raise appropriate ValueError.

    :type value: str
    :param value: value of the argument.

    :type name: str
    :param name: name of the argument.
    """
    if not value:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format(name))
    return value


def validate_single_select(value, name, single_select_choices):
    """
    Validate the status has valid input.

    :type value: str
    param status: input from user to enable or disable the status

    :type name: str
    param name: name of the argument to validate

    :type single_select_choices: List
    param single_select_choices: list of choices to single select for an argument

    :return: status value
    :rtype: str
    """
    if value not in single_select_choices:
        raise ValueError(MESSAGES['VALIDATE_SINGLE_SELECT'].format(name, ', '.join(single_select_choices)))
    return value


def validate_list_retrohunts_args(args):
    """
    Return and validate page_size, retrohunts_list_all_versions, page_token, rule_id, state.

    :type args: Dict[str, Any]
    :param args: contains all arguments for gcb-list-retrohunts command

    :return: Dictionary containing values of page_size, retrohunts_list_all_versions, page_token, rule_id, state
     or raise ValueError if the arguments are invalid
    :rtype: Dict[str, Any]
    """
    page_size = args.get('page_size', 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))
    retrohunts_for_all_versions = argToBoolean(args.get('retrohunts_for_all_versions', False))
    page_token = args.get('page_token')
    rule_id = args.get('id')
    state = args.get('state')

    valid_args = {'page_size': page_size, 'page_token': page_token, 'rule_id': rule_id,
                  'retrohunts_for_all_versions': retrohunts_for_all_versions, 'state': state}
    if rule_id and '@' in rule_id and retrohunts_for_all_versions:
        raise ValueError("Invalid value in argument 'id'. Expected rule_id.")

    return valid_args


def get_params_for_reputation_command():
    """
    Get Demisto parameters related to the reputation command.

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


def validate_configuration_parameters(param: dict[str, Any]):
    """
    Check whether entered configuration parameters are valid or not.

    :type param: dict
    :param param: Dictionary of demisto configuration parameter

    :return: raise ValueError if any configuration parameter is not in valid format else returns None
    :rtype: None
    """
    # get configuration parameters
    service_account_json = param.get('service_account_credential', '')
    first_fetch = param.get('first_fetch', DEFAULT_FIRST_FETCH).lower()
    page_size = param.get('max_fetch', '10')
    time_window = param.get('time_window', '15')

    detection_by_ids = param.get('fetch_detection_by_ids') or ""
    detection_by_id = [r_v_id.strip() for r_v_id in detection_by_ids.split(',')]

    if param.get('backstory_alert_type', 'ioc domain matches').lower() == 'detection alerts' and not \
            param.get('fetch_all_detections', False) and not get_unique_value_from_list(detection_by_id):
        raise ValueError('Please enter one or more Rule ID(s) or Version ID(s) as value of "Detections to '
                         'fetch by Rule ID or Version ID" or check the checkbox "Fetch all rules '
                         'detections" to fetch detections.')

    if param.get('backstory_alert_type', 'ioc domain matches').lower() == 'curated rule detection alerts' and not \
            detection_by_ids:
        raise ValueError(MESSAGES['PROVIDE_CURATED_RULE_ID'])

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
        arg_to_datetime(first_fetch, 'First fetch time')

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


def validate_page_size(page_size):
    """
    Validate that page size parameter is in numeric format or not.

    :type page_size: str
    :param page_size: this value will be check as numeric or not

    :return: True if page size is valid  else raise ValueError
    :rtype: bool
    """
    if not page_size or not str(page_size).isdigit() or int(page_size) == 0:
        raise ValueError('Page size must be a non-zero and positive numeric value')
    return True


def validate_preset_time_range(value):
    """
    Validate that preset_time_range parameter is in valid format or not and \
    strip the keyword 'Last' to extract the date range if validation is through.

    :type value: str
    :param value: this value will be check as valid or not

    :return: 1 Day, 7 Days, 15 Days, 30 Days or ValueError
    :rtype: string or Exception
    """
    value_split = value.split(' ')
    try:
        if value_split[0].lower() != 'last':
            raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])

        day = int(value_split[1])

        if day not in [1, 7, 15, 30]:
            raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])

        if value_split[2].lower() not in ['day', 'days']:
            raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])
    except Exception:
        raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])
    return value_split[1] + ' ' + value_split[2].lower()


def get_chronicle_default_date_range(days=DEFAULT_FIRST_FETCH, arg_name='start_time'):
    """
    Get Chronicle Backstory default date range(last 3 days).

    :return: start_date, end_date (ISO date in UTC)
    :rtype: string
    """
    start_date, end_date = arg_to_datetime(days, arg_name), datetime.now()
    return start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)  # type: ignore


def get_artifact_type(value):
    """
    Derive the input value's artifact type based on the regex match. \
    The returned artifact_type is compliant with the Search API.

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


def prepare_hr_for_assets(asset_identifier_value, asset_identifier_key, data):
    """
    Prepare HR for assets.

    :param asset_identifier_value: Value of asset identifier
    :param asset_identifier_key: Key of asset identifier
    :param data: response from API endpoint
    :return: HR dictionary
    """
    tabular_data_dict = {}
    tabular_data_dict['Host Name'] = asset_identifier_value if asset_identifier_key == 'hostname' else '-'
    tabular_data_dict['Host IP'] = asset_identifier_value if asset_identifier_key == 'assetIpAddress' else '-'
    tabular_data_dict['Host MAC'] = asset_identifier_value if asset_identifier_key == 'MACAddress' else '-'
    tabular_data_dict[FIRST_ACCESSED_TIME] = data.get('firstSeenArtifactInfo', {}).get('seenTime', '-')
    tabular_data_dict[LAST_ACCESSED_TIME] = data.get('lastSeenArtifactInfo', {}).get('seenTime', '-')
    return tabular_data_dict


def parse_assets_response(response: dict[str, Any], artifact_type, artifact_value):
    """
    Parse response of list assets within the specified time range.

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
    tabular_data_list = []
    host_context = []

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
                demisto.debug(f'Unknown asset identifier found - {asset_identifier_key}. Skipping this asset')
                continue
        ctx_primary_key = CONTEXT_KEY_DICT[asset_identifier_key]

        # Preparing GCB custom context
        gcb_context_data = {}
        gcb_context_data[ctx_primary_key] = asset_identifier_value
        gcb_context_data['FirstAccessedTime'] = data.get('firstSeenArtifactInfo', {}).get('seenTime', '')
        gcb_context_data['LastAccessedTime'] = data.get('lastSeenArtifactInfo', {}).get('seenTime', '')
        gcb_context_data['Accessed' + ARTIFACT_NAME_DICT[artifact_type]] = artifact_value
        context_data[CHRONICLE_OUTPUT_PATHS['Asset'].format(ctx_primary_key)].append(gcb_context_data)

        # Response for HR
        tabular_data_dict = prepare_hr_for_assets(asset_identifier_value, asset_identifier_key, data)
        tabular_data_list.append(tabular_data_dict)

        # Populating Host context for list of assets
        host_context.append({HOST_CTX_KEY_DICT[asset_identifier_key]: asset_identifier_value})
    return context_data, tabular_data_list, host_context


def get_default_command_args_value(args: dict[str, Any], max_page_size=10000, date_range=None):
    """
    Validate and return command arguments default values as per Chronicle Backstory.

    :type args: dict
    :param args: contain all arguments for command

    :type max_page_size: int
    :param max_page_size: maximum allowed page size

    :type date_range: string
    :param date_range: The date range to be parsed

    :return : start_time, end_time, page_size, reference_time
    :rtype : str, str, int, Optional[str]
    """
    preset_time_range = args.get('preset_time_range', None)
    reference_time = None
    if preset_time_range:
        preset_time_range = validate_preset_time_range(preset_time_range)
        start_time, end_time = get_chronicle_default_date_range(preset_time_range, 'preset_time_range')
    else:
        if date_range is None:
            date_range = DEFAULT_FIRST_FETCH
        start_time, end_time = get_chronicle_default_date_range(days=date_range)
        if args.get('start_time'):
            start_time = arg_to_datetime(args.get('start_time'), 'start_time').strftime(DATE_FORMAT)  # type: ignore
        if args.get('end_time'):
            end_time = arg_to_datetime(args.get('end_time'), 'end_time').strftime(DATE_FORMAT)  # type: ignore
    if args.get('reference_time'):
        reference_time = arg_to_datetime(args.get('reference_time'), 'reference_time') \
            .strftime(DATE_FORMAT)  # type: ignore

    page_size = args.get('page_size', 10000)
    validate_page_size(page_size)
    if int(page_size) > max_page_size:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(max_page_size))
    return start_time, end_time, page_size, reference_time


def get_gcb_udm_search_command_args_value(args: dict[str, Any], max_limit=1000, date_range=None):
    """
    Validate and return gcb-udm-search command arguments default values as per Chronicle Backstory.

    :type args: dict
    :param args: Contain all arguments for command.

    :type max_limit: int
    :param max_limit: Maximum allowed limit.

    :type date_range: string
    :param date_range: The date range to be parsed.

    :return : start_time, end_time, limit, query
    :rtype : str, str, int, str
    """
    query = args.get('query', '')
    if not query:
        raise ValueError(MESSAGES['QUERY_REQUIRED'])
    query = urllib.parse.quote(args.get('query', ''))
    preset_time_range = args.get('preset_time_range', None)
    if preset_time_range:
        preset_time_range = validate_preset_time_range(preset_time_range)
        start_time, end_time = get_chronicle_default_date_range(preset_time_range, 'preset_time_range')
    else:
        if date_range is None:
            date_range = DEFAULT_FIRST_FETCH
        start_time, end_time = get_chronicle_default_date_range(days=date_range)
        if args.get('start_time'):
            start_time = arg_to_datetime(args.get('start_time'), 'start_time').strftime(DATE_FORMAT)  # type: ignore
        if args.get('end_time'):
            end_time = arg_to_datetime(args.get('end_time'), 'end_time').strftime(DATE_FORMAT)  # type: ignore

    limit = args.get('limit', 200)
    if not limit or not str(limit).isdigit() or int(limit) == 0:
        raise ValueError(MESSAGES["INVALID_LIMIT_TYPE"])
    if int(limit) > max_limit:
        raise ValueError(MESSAGES["INVALID_LIMIT_RANGE"].format(max_limit))

    return start_time, end_time, limit, query


def parse_error_message(error: str, region: str):
    """
    Extract error message from error object.

    :type error: str
    :param error: Error string response to be parsed
    :type region: str
    :param region: Region value based on the location of the chronicle backstory instance.

    :return: error message
    :rtype: str
    """
    try:
        json_error = json.loads(error)
        if isinstance(json_error, list):
            json_error = json_error[0]
    except json.decoder.JSONDecodeError:
        if region not in REGIONS.values() and '404' in error:
            error_message = 'Invalid response from Chronicle API. Check the provided "Other Region" parameter.'
        else:
            error_message = 'Invalid response received from Chronicle API. Response not in JSON format.'
        demisto.debug(f'{error_message} Response - {error}')
        return error_message

    if json_error.get('error', {}).get('code') == 403:
        return 'Permission denied'
    return json_error.get('error', {}).get('message', '')


def transform_to_informal_time(total_time, singular_expected_string, plural_expected_string):
    """
    Convert to informal time from date to current time.

    :type total_time: float
    :param total_time: string of datetime object

    :type singular_expected_string: string
    :param singular_expected_string: expected string if total_time is 1

    :type plural_expected_string: string
    :param plural_expected_string: expected string if total_time is more than 1

    :return: informal time from date to current time
    :rtype: str
    """
    return singular_expected_string if total_time == 1 else str(total_time) + plural_expected_string


def get_informal_time(date):
    """
    Convert to informal time from date to current time.

    :type date: string
    :param date: string of datetime object

    :return: informal time from date to current time
    :rtype: str
    """
    current_time = datetime.utcnow()
    previous_time = parse_date_string(date)

    total_time = (current_time - previous_time).total_seconds()

    if 0 < total_time < 60:
        return transform_to_informal_time(total_time, 'a second ago', ' seconds ago')
    total_time = round(total_time / 60)
    if 0 < total_time < 60:
        return transform_to_informal_time(total_time, 'a minute ago', ' minutes ago')
    total_time = round(total_time / 60)
    if 0 < total_time < 24:
        return transform_to_informal_time(total_time, 'an hour ago', ' hours ago')
    total_time = round(total_time / 24)
    if 0 < total_time < 31:
        return transform_to_informal_time(total_time, 'a day ago', ' days ago')
    total_time = round(total_time / 31)
    if 0 < total_time < 12:
        return transform_to_informal_time(total_time, 'a month ago', ' months ago')
    total_time = round((total_time * 31) / 365)
    return transform_to_informal_time(total_time, 'a year ago', ' years ago')


def parse_list_ioc_response(ioc_matches):
    """
    Parse response of list iocs within the specified time range. \
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
        artifact = ioc_match.get('artifact', {})
        artifact_value = ""
        # Confirm that artifact is not empty and it is dictionary.
        if artifact and isinstance(artifact, dict):
            artifact_value = list(artifact.values())[0]
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
                'Artifact': '[{}]({})'.format(artifact_value, ioc_match.get('uri', [''])[0]),
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
        if artifact.get('domainName'):
            domain_std_context.append({'Name': artifact_value})

        # prepare context data for IoCs
        context.append({
            'Artifact': artifact_value,
            'IocIngestTime': ingest_time,
            'FirstAccessedTime': first_seen_time,
            'LastAccessedTime': last_seen_time,
            'Sources': sources
        })

    return {'hr_ioc_matches': hr_ioc_matches, 'domain_std_context': domain_std_context, 'context': context}


def is_category_malicious(category, reputation_params):
    """Determine if category is malicious in reputation_params."""
    return category and category.lower() in reputation_params['malicious_categories']


def is_severity_malicious(severity, reputation_params):
    """Determine if severity is malicious in reputation_params."""
    return severity and severity.lower() in reputation_params['override_severity_malicious']


def is_confidence_score_malicious(confidence_score, params):
    """Determine if confidence score is malicious in reputation_params."""
    return is_int_type_malicious_score(confidence_score, params) or is_string_type_malicious_score(confidence_score,
                                                                                                   params)


def is_string_type_malicious_score(confidence_score, params):
    """Determine if string type confidence score is malicious in reputation_params."""
    return not isinstance(confidence_score, int) and CONFIDENCE_LEVEL_PRIORITY.get(
        params['override_confidence_level_malicious'], 10) <= CONFIDENCE_LEVEL_PRIORITY.get(confidence_score.lower(),
                                                                                            -1)


def is_int_type_malicious_score(confidence_score, params):
    """Determine if integer type confidence score is malicious in reputation_params."""
    return params['override_confidence_score_malicious_threshold'] and isinstance(confidence_score, int) and int(
        params['override_confidence_score_malicious_threshold']) <= confidence_score


def is_category_suspicious(category, reputation_params):
    """Determine if category is suspicious in reputation_params."""
    return category and category.lower() in reputation_params['suspicious_categories']


def is_severity_suspicious(severity, reputation_params):
    """Determine if severity is suspicious in reputation_params."""
    return severity and severity.lower() in reputation_params['override_severity_suspicious']


def is_confidence_score_suspicious(confidence_score, params):
    """Determine if confidence score is suspicious in reputation_params."""
    return is_int_type_suspicious_score(confidence_score, params) or is_string_type_suspicious_score(confidence_score,
                                                                                                     params)


def is_string_type_suspicious_score(confidence_score, params):
    """Determine if string type confidence score is suspicious in reputation_params."""
    return not isinstance(confidence_score, int) and CONFIDENCE_LEVEL_PRIORITY.get(
        params['override_confidence_level_suspicious'], 10) <= CONFIDENCE_LEVEL_PRIORITY.get(confidence_score.lower(),
                                                                                             -1)


def is_int_type_suspicious_score(confidence_score, params):
    """Determine if integer type confidence score is suspicious in reputation_params."""
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


def prepare_hr_for_ioc_details(addresses, hr_table_row):
    """
    Prepare HR for IOC Details.

    :param hr_table_row: dictionary containing HR details
    :param addresses: List of addresses
    :return: updated HR dictionary
    """
    address_data = []
    for address in addresses:
        if address.get('domain'):
            address_data.append({
                'Domain': address['domain'],
                'Port': address.get('port', [])
            })
            hr_table_row['Domain'] = address['domain']
        if address.get('ipAddress'):
            address_data.append({
                'IpAddress': address['ipAddress'],
                'Port': address.get('port', [])
            })
            hr_table_row[IP_ADDRESS] = address['ipAddress']
            address_data = remove_empty_elements(address_data)
    return address_data, hr_table_row


def get_context_for_ioc_details(sources, artifact_indicator, artifact_type, is_reputation_command=True):
    """
    Generate context data for reputation command and ioc details command.

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
            IP_ADDRESS: '-',
            'Category': category,
            CONFIDENCE_SCORE: confidence_score,
            'Severity': severity,
            FIRST_ACCESSED_TIME: source.get('firstActiveTime'),
            LAST_ACCESSED_TIME: source.get('lastActiveTime')
        }

        # Parsing the Addresses data to fetch IP and Domain data for context
        address_data, hr_table_row = prepare_hr_for_ioc_details(source.get('addresses', []), hr_table_row)
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
            'Vendor': VENDOR,
            'Score': dbot_score_max,
            'Reliability': demisto.params().get('integrationReliability')
        }
        if dbot_score_max == 3:
            standard_context['Malicious'] = {
                'Vendor': VENDOR,
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
    Parse alert info of alerts.

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
    Call list IOC API with :start_time, :end_time and :max_fetch.

    filter_severity to filter out an alert after getting a response from API. Passing ALL will not filter any data

    :param client_obj perform API request
    :param start_time
    :param max_fetch

    return events - list of dict representing events
    """
    request_url = f'{BACKSTORY_API_V1_URL}/ioc/listiocs?start_time={start_time}&page_size={max_fetch}'

    response_body = validate_response(client_obj, request_url)
    ioc_matches = response_body.get('response', {}).get('matches', [])
    parsed_ioc = parse_list_ioc_response(ioc_matches)
    return parsed_ioc['context']


def get_gcb_alerts(client_obj, start_time, end_time, max_fetch, filter_severity):
    """
    Call list alert API with :start_time, :end_time and :max_fetch.

    filter_severity to filter out an alert after getting a response from API. Passing ALL will not filter any data

    :param client_obj perform API request
    :param start_time
    :param end_time
    :param max_fetch
    :param filter_severity

    return events - list of dict representing events
    """
    request_url = f'{BACKSTORY_API_V1_URL}/alert/listalerts?start_time={start_time}&end_time={end_time}&page_size={max_fetch}'
    demisto.debug(f"[CHRONICLE] Request URL for fetching alerts: {request_url}")

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
    Call appropriate reputation command.

    Common method for reputation commands to accept argument as a comma-separated values and converted into list \
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
    Group alerts by assets.

    This method converts assets with multiple alerts into assets per asset_alert and \
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
                if info['Timestamp'] >= asset_alert_hr[LAST_SEEN_AGO]:
                    asset_alert_hr[LAST_SEEN_AGO] = info['Timestamp']
                    asset_alert_hr[LAST_SEEN] = get_informal_time(info['Timestamp'])
                    asset_alert_ctx['LastSeen'] = info['Timestamp']
                elif info['Timestamp'] <= asset_alert_hr[FIRST_SEEN_AGO]:
                    asset_alert_hr[FIRST_SEEN_AGO] = info['Timestamp']
                    asset_alert_hr[FIRST_SEEN] = get_informal_time(info['Timestamp'])
                    asset_alert_ctx['FirstSeen'] = info['Timestamp']
            else:
                asset_alert_hr[FIRST_SEEN_AGO] = info['Timestamp']
                asset_alert_hr[FIRST_SEEN] = get_informal_time(info['Timestamp'])
                asset_alert_hr[LAST_SEEN_AGO] = info['Timestamp']
                asset_alert_hr[LAST_SEEN] = get_informal_time(info['Timestamp'])

                asset_alert_ctx['FirstSeen'] = info['Timestamp']
                asset_alert_ctx['LastSeen'] = info['Timestamp']

            asset_alert_ctx.setdefault('Occurrences', []).append(info['Timestamp'])
            asset_alert_ctx['Alerts'] = asset_alert_hr['Alerts'] = asset_alert_ctx.get('Alerts', 0) + 1
            asset_alert_ctx['Asset'] = asset_alert['AssetName']
            asset_alert_ctx['AlertName'] = asset_alert_hr[ALERT_NAMES] = info['Name']
            asset_alert_ctx['Severities'] = asset_alert_hr['Severities'] = info['Severity']
            asset_alert_ctx['Sources'] = asset_alert_hr['Sources'] = info['SourceProduct']

            asset_alert_hr['Asset'] = '[{}]({})'.format(asset_alert['AssetName'], info.get('Uri'))

            unique_asset_alert_ctx[asset_alert_key] = asset_alert_ctx
            unique_asset_alerts_hr[asset_alert_key] = asset_alert_hr

    return unique_asset_alerts_hr, unique_asset_alert_ctx


def convert_alerts_into_hr(events):
    """
    Convert alerts into human readable by parsing alerts.

    :param events: events from the response
    :return: human readable for alerts
    """
    data = group_infos_by_alert_asset_name(events)[0].values()
    return tableToMarkdown('Security Alert(s)', list(data),
                           ['Alerts', 'Asset', ALERT_NAMES, FIRST_SEEN, LAST_SEEN, 'Severities',
                            'Sources'],
                           removeNull=True)


def get_asset_identifier_details(asset_identifier):
    """
    Return asset identifier detail such as hostname, ip, mac.

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
    Get more information for event from response.

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
    Convert response into Context data.

    :param events: List of events
    :type events: list

    :return: list of context data
    """
    events_ec = []
    for event in events:
        event_dict = {}
        if 'metadata' in event:
            event_dict.update(event.pop('metadata'))
        event_dict.update(event)
        events_ec.append(event_dict)

    return events_ec


def get_list_events_hr(events):
    """
    Convert events response into human readable.

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


def get_udm_search_events_hr(events: list) -> str:
    """
    Convert UDM search events response into human-readable.

    :param events: List of events.
    :type events: List

    :return: Returns human-readable string for gcb-udm-search command.
    :rtype: str
    """
    hr_dict = []
    for event in events:
        # Get queried domain, process command line, file use by process information
        more_info = get_more_information(event)
        security_result_list = []
        for security_result in event.get('securityResult', []):
            security_result_info = []
            severity = security_result.get('severity')
            summary = security_result.get('summary')
            action = security_result.get('action', [])
            rule_name = security_result.get('ruleName')
            if severity:
                security_result_info.append(f'**Severity:** {severity}')
            if summary:
                security_result_info.append(f'**Summary:** {summary}')
            if action and isinstance(action, list):
                security_result_info.append('**Actions:** {}'.format(', '.join(action)))
            if rule_name:
                security_result_info.append(f'**Rule Name:** {rule_name}')
            security_result_list.append('\n'.join(security_result_info))
        security_results = '\n\n'.join(security_result_list)
        hr_dict.append({
            'Event ID': event.get('metadata', {}).get('id'),
            'Event Timestamp': event.get('metadata', {}).get('eventTimestamp', ''),
            'Event Type': event.get('metadata', {}).get('eventType', ''),
            'Security Results': security_results,
            'Principal Asset Identifier': get_asset_identifier_details(event.get('principal', {})),
            'Target Asset Identifier': get_asset_identifier_details(event.get('target', {})),
            'Description': event.get('metadata', {}).get('description'),
            'Product Name': event.get('metadata', {}).get('productName'),
            'Vendor Name': event.get('metadata', {}).get('vendorName'),
            'Queried Domain': more_info[0],
            'Process Command Line': re.escape(more_info[1]),
            'File In Use By Process': re.escape(more_info[2]),
        })

    hr = tableToMarkdown('Event(s) Details', hr_dict,
                         ['Event ID', 'Event Timestamp', 'Event Type', 'Security Results', 'Principal Asset Identifier',
                          'Target Asset Identifier', 'Description', 'Product Name', 'Vendor Name', 'Queried Domain',
                          'File In Use By Process', 'Process Command Line'], removeNull=True)
    return hr


def validate_and_parse_detection_start_end_time(args: dict[str, Any]) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Validate and return detection_start_time and detection_end_time as per Chronicle Backstory or \
    raise a ValueError if the given inputs are invalid.

    :type args: dict
    :param args: contains all arguments for command

    :return : detection_start_time, detection_end_time: Detection start and end time in the format API accepts
    :rtype : Tuple[Optional[str], Optional[str]]
    """
    detection_start_time = arg_to_datetime(args.get('start_time'), 'start_time') if args.get('start_time') \
        else arg_to_datetime(args.get('detection_start_time'), 'detection_start_time')
    detection_end_time = arg_to_datetime(args.get('end_time'), 'end_time') if args.get('end_time') \
        else arg_to_datetime(args.get('detection_end_time'), 'detection_end_time')

    list_basis = args.get('list_basis', '')
    if list_basis and not detection_start_time and not detection_end_time:
        raise ValueError("To sort detections by \"list_basis\", either \"start_time\" or \"end_time\" argument is "
                         "required.")

    if detection_start_time:
        detection_start_time = detection_start_time.strftime(DATE_FORMAT)  # type: ignore
    if detection_end_time:
        detection_end_time = detection_end_time.strftime(DATE_FORMAT)  # type: ignore
    return detection_start_time, detection_end_time


def validate_and_parse_curatedrule_detection_start_end_time(args: dict[str, Any]) -> tuple[
        Optional[datetime], Optional[datetime]]:
    """
    Validate and return detection_start_time and detection_end_time as per Chronicle Backstory or \
    raise a ValueError if the given inputs are invalid.

    :type args: dict
    :param args: Contains all arguments for command.

    :return : detection_start_time, detection_end_time: Detection start and End time in the format API accepts.
    :rtype : Tuple[Optional[str], Optional[str]]
    """
    detection_start_time = arg_to_datetime(args.get('start_time'), 'start_time')
    detection_end_time = arg_to_datetime(args.get('end_time'), 'end_time')

    if detection_start_time:
        detection_start_time = detection_start_time.strftime(DATE_FORMAT)  # type: ignore
    if detection_end_time:
        detection_end_time = detection_end_time.strftime(DATE_FORMAT)  # type: ignore
    return detection_start_time, detection_end_time


def validate_and_parse_list_detections_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Return and validate page_size, detection_start_time and detection_end_time.

    :type args: Dict[str, Any]
    :param args: contains all arguments for list-detections command

    :return: Dictionary containing values of page_size, detection_start_time and detection_end_time
     or raise ValueError if the arguments are invalid
    :rtype: Dict[str, Any]
    """
    page_size = args.get('page_size', 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))

    rule_id = args.get('id', '')
    detection_for_all_versions = argToBoolean(args.get('detection_for_all_versions', False))
    if detection_for_all_versions and not rule_id:
        raise ValueError('If "detection_for_all_versions" is true, rule id is required.')

    detection_start_time, detection_end_time = validate_and_parse_detection_start_end_time(args)

    valid_args = {'page_size': page_size, 'detection_start_time': detection_start_time,
                  'detection_end_time': detection_end_time, 'detection_for_all_versions': detection_for_all_versions}

    return valid_args


def validate_and_parse_list_curatedrule_detections_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Return and validate page_size, detection_start_time and detection_end_time.

    :type args: Dict[str, Any]
    :param args: Contains all arguments for list-curatedrule-detections command.

    :return: Dictionary containing values of page_size, detection_start_time and detection_end_time
     or raise ValueError if the arguments are invalid.
    :rtype: Dict[str, Any]
    """
    page_size = args.get('page_size', 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))

    if not args.get('id'):
        raise ValueError(MESSAGES["CURATED_RULE_ID_REQUIRED"])

    detection_start_time, detection_end_time = validate_and_parse_curatedrule_detection_start_end_time(args)

    valid_args = {'page_size': page_size, 'detection_start_time': detection_start_time,
                  'detection_end_time': detection_end_time}

    return valid_args


def validate_list_asset_aliases_args(asset_identifier_type: Optional[str], asset_identifier: str,
                                     page_size: Optional[int]) -> None:
    """
    Validate parameter for list asset aliases command.

    :type asset_identifier_type: str
    :param asset_identifier_type: Type of the asset identifier.

    :type asset_identifier: str
    :param asset_identifier: Value of the asset identifier.

    :type page_size: int
    :param page_size: Maximum number of results to return.
    """
    if not asset_identifier:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format('asset_identifier'))

    if not asset_identifier_type:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format(
            'asset_identifier_type', ASSET_IDENTIFIER_NAME_DICT.keys()))

    validate_page_size(page_size)
    if int(page_size) > 10000 or int(page_size) < 0:  # type: ignore
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format('10000'))


def validate_list_curated_rules_args(page_size: Optional[int]) -> None:
    """
    Validate parameter for list curated rules command.

    :type page_size: int
    :param page_size: Maximum number of results to return.
    """
    validate_page_size(page_size)
    if int(page_size) > 1000 or int(page_size) < 0:  # type: ignore
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format('1000'))


def validate_list_user_aliases_args(user_identifier_type: Optional[str], user_identifier: str,
                                    page_size: Optional[int]) -> None:
    """
    Validate parameter for list user aliases command.

    :type user_identifier_type: str
    :param user_identifier_type: Type of the user identifier.

    :type user_identifier: str
    :param user_identifier: Value of the user identifier.

    :type page_size: int
    :param page_size: Maximum number of results to return.
    """
    if not user_identifier:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format('user_identifier'))

    if not user_identifier_type:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format(
            'user_identifier_type', USER_IDENTIFIER_NAME_DICT.keys()))

    validate_page_size(page_size)
    if int(page_size) > 10000 or int(page_size) < 0:  # type: ignore
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format('10000'))


def get_hr_for_event_in_detection(event: dict[str, Any]) -> str:
    """
    Return a string containing event information for an event.

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
        event_info.append(f'**Event Timestamp:** {event_timestamp}')
    if event_type:
        event_info.append(f'**Event Type:** {event_type}')
    if principal_asset_identifier:
        event_info.append(f'**Principal Asset Identifier:** {principal_asset_identifier}')
    if target_asset_identifier:
        event_info.append(f'**Target Asset Identifier:** {target_asset_identifier}')
    if queried_domain:
        event_info.append(f'**Queried Domain:** {queried_domain}')
    if process_command_line:
        event_info.append(f'**Process Command Line:** {process_command_line}')
    if file_in_use_by_process:
        event_info.append(f'**File In Use By Process:** {file_in_use_by_process}')
    return '\n'.join(event_info)


def get_events_hr_for_detection(events: list[dict[str, Any]]) -> str:
    """
    Convert events response related to the specified detection into human readable.

    :param events: list of events
    :type events: list

    :return: returns human readable string for the events related to the specified detection
    :rtype: str
    """
    events_hr = []
    for event in events:
        events_hr.append(get_hr_for_event_in_detection(event))

    return '\n\n'.join(events_hr)


def get_event_list_for_detections_hr(result_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert events response related to the specified detection into list of events for command's human readable.

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


def get_event_list_for_detections_context(result_events: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Convert events response related to the specified detection into list of events for command's context.

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


def get_list_detections_hr(detections: list[dict[str, Any]], rule_or_version_id: str) -> str:
    """
    Convert detections response into human readable.

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
    if rule_uri and rule_or_version_id:
        rule_uri = rule_uri.split('/')
        rule_uri = f'{rule_uri[0]}//{rule_uri[2]}/ruleDetections?ruleId={rule_or_version_id}'
        hr_title = 'Detection(s) Details For Rule: [{}]({})'. \
            format(detections[0].get('detection', {})[0].get('ruleName', ''), rule_uri)
    else:
        hr_title = 'Detection(s)'
    hr = tableToMarkdown(hr_title, hr_dict, ['Detection ID', 'Detection Type', 'Detection Time', 'Events',
                                             'Alert State'], removeNull=True)
    return hr


def get_list_curatedrule_detections_hr(detections: list[dict[str, Any]], curatedrule_id: str) -> str:
    """
    Convert curated rule detection response into human-readable.

    :param detections: List of detections.
    :type detections: List

    :param curatedrule_id: Curated Rule ID for which detections will be fetched.
    :type curatedrule_id: str

    :return: Returns human-readable string for gcb-list-curatedrule-detections command.
    :rtype: str
    """
    hr_dict = []
    for detection in detections:
        events = get_event_list_for_detections_hr(detection.get('collectionElements', []))
        detection_details = detection.get('detection', [{}])
        hr_dict.append({
            'Detection ID': "[{}]({})".format(detection.get('id', ''),
                                              detection_details[0].get('urlBackToProduct', '')),
            'Description': detection_details[0].get('description'),
            'Detection Type': detection.get('type', ''),
            'Detection Time': detection.get('detectionTime', ''),
            'Events': get_events_hr_for_detection(events),
            'Alert State': detection_details[0].get('alertState', ''),
            'Detection Severity': detection_details[0].get('severity', ''),
            'Detection Risk-Score': detection_details[0].get('riskScore', ''),
        })
    rule_uri = detections[0].get('detection', {})[0].get('urlBackToProduct', '')
    if rule_uri and curatedrule_id:
        rule_uri = rule_uri.split('/')
        rule_uri = f'{rule_uri[0]}//{rule_uri[2]}/ruleDetections?ruleId={curatedrule_id}'
        hr_title = 'Curated Detection(s) Details For Rule: [{}]({})'.format(
            detections[0].get('detection', {})[0].get('ruleName', ''), rule_uri)
    else:
        hr_title = 'Curated Detection(s)'
    hr = tableToMarkdown(hr_title, hr_dict,
                         ['Detection ID', 'Description', 'Detection Type', 'Detection Time', 'Events',
                          'Alert State', 'Detection Severity', 'Detection Risk-Score'], removeNull=True)
    return hr


def get_events_context_for_detections(result_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert events in response into Context data for events associated with a detection.

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
            if 'metadata' in event:
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


def get_events_context_for_curatedrule_detections(result_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert events in response into Context data for events associated with a curated rule detection.

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
            if 'metadata' in event:
                event_dict.update(event.pop('metadata'))
            principal_asset_identifier = get_asset_identifier_details(event.get('principal', {}))
            target_asset_identifier = get_asset_identifier_details(event.get('target', {}))
            if event.get('securityResult'):
                severity = []
                for security_result in event.get('securityResult', []):
                    if isinstance(security_result, dict) and 'severity' in security_result:
                        severity.append(security_result.get('severity'))
                if severity:
                    event_dict.update({'eventSeverity': ','.join(severity)})  # type: ignore
            if principal_asset_identifier:
                event_dict.update({'principalAssetIdentifier': principal_asset_identifier})
            if target_asset_identifier:
                event_dict.update({'targetAssetIdentifier': target_asset_identifier})
            event_dict.update(event)
            reference.append(event_dict)
        collection_element_dict = {'references': reference, 'label': collection_element.get('label', '')}
        events_ec.append(collection_element_dict)

    return events_ec


def get_context_for_detections(detection_resp: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Convert detections response into Context data.

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


def get_context_for_curatedrule_detections(detection_resp: dict[str, Any]) -> tuple[
        list[dict[str, Any]], dict[str, str]]:
    """
    Convert curated rule detections response into Context data.

    :param detection_resp: Response fetched from the API call for curated rule detections.
    :type detection_resp: Dict[str, Any]

    :return: list of curated rule detections and token to populate context data.
    :rtype: Tuple[List[Dict[str, Any]], Dict[str, str]]
    """
    detections_ec = []
    token_ec = {}
    next_page_token = detection_resp.get('nextPageToken')
    if next_page_token:
        token_ec = {'name': 'gcb-list-curatedrule-detections', 'nextPageToken': next_page_token}
    detections = detection_resp.get('curatedRuleDetections', [])
    for detection in detections:
        detection_dict = detection
        result_events = detection.get('collectionElements', [])
        if result_events:
            detection_dict['collectionElements'] = get_events_context_for_curatedrule_detections(result_events)

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
        -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-list-detections command.

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

    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_or_version_id}/detections?pageSize={page_size}' \


    # Append parameters if specified
    if detection_start_time:
        request_url += f'&startTime={detection_start_time}'

    if detection_end_time:
        request_url += f'&endTime={detection_end_time}'

    if alert_state:
        request_url += f'&alertState={alert_state}'

    if list_basis:
        request_url += f'&listBasis={list_basis}'

    if page_token:
        request_url += f'&page_token={page_token}'
    # get list of detections from Chronicle Backstory
    json_data = validate_response(client_obj, request_url)
    raw_resp = deepcopy(json_data)
    parsed_ec, token_ec = get_context_for_detections(json_data)
    ec: dict[str, Any] = {
        CHRONICLE_OUTPUT_PATHS['Detections']: parsed_ec
    }
    if token_ec:
        ec.update({CHRONICLE_OUTPUT_PATHS['Token']: token_ec})
    return ec, raw_resp


def get_curatedrule_detections(client_obj, curatedrule_id: str, page_size: str, detection_start_time: str,
                               detection_end_time: str, page_token: str, alert_state: str, list_basis: str = None) \
        -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-list-curatedrule-detections command.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.
    :type curatedrule_id: str
    :param curatedrule_id: curatedrule_id to fetch the detections for.
    :type page_size: str
    :param page_size: Number of detections to fetch at a time.
    :type detection_start_time: str
    :param detection_start_time: Start time of the time range to return detections for, filtering by the detection
    field specified in the list_basis parameter.
    :type detection_end_time: str
    :param detection_end_time: End time of the time range to return detections for, filtering by the detection
    field specified by the list_basis parameter.
    :type page_token: str
    :param page_token: The token for the page from which the detections should be fetched.
    :type alert_state: str
    :param alert_state: Filter detections based on whether the alert state is ALERTING or NOT_ALERTING.
    :type list_basis: str
    :param list_basis: Sort detections by DETECTION_TIME or by CREATED_TIME.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, raw_resp: Context data and raw response for the fetched detections
    """

    request_url = f'{BACKSTORY_API_V2_URL}/detect/curatedRules/{curatedrule_id}/detections?pageSize={page_size}' \


    # Append parameters if specified
    if detection_start_time:
        request_url += f'&startTime={detection_start_time}'

    if detection_end_time:
        request_url += f'&endTime={detection_end_time}'

    if alert_state:
        request_url += f'&alertState={alert_state}'

    if list_basis:
        request_url += f'&listBasis={list_basis}'

    if page_token:
        request_url += f'&page_token={page_token}'
    # get list of detections from Chronicle Backstory
    json_data = validate_response(client_obj, request_url)
    raw_resp = deepcopy(json_data)
    parsed_ec, token_ec = get_context_for_curatedrule_detections(json_data)
    ec: dict[str, Any] = {CHRONICLE_OUTPUT_PATHS['CuratedRuleDetections']: parsed_ec}
    if token_ec:
        ec.update({CHRONICLE_OUTPUT_PATHS['Token']: token_ec})
    return ec, raw_resp


def generate_delayed_start_time(time_window: str, start_time: str) -> str:
    """
    Generate the delayed start time accordingly after validating the time window provided by user.

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
    delayed_start_time = delayed_start_time - timedelta(minutes=int(time_window))  # type: ignore
    delayed_start_time = datetime.strftime(delayed_start_time, DATE_FORMAT)  # type: ignore

    return delayed_start_time


def deduplicate_events_and_create_incidents(contexts: list, event_identifiers: list[str], user_alert: bool = False):
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
    incidents: list[dict[str, Any]] = []
    new_event_hashes = []
    for event in contexts:
        try:
            event_hash = sha256(str(event).encode()).hexdigest()  # NOSONAR
            new_event_hashes.append(event_hash)
        except Exception as e:
            demisto.error("[CHRONICLE] Skipping insertion of current event since error occurred while calculating"
                          f" Hash for the event {event}. Error: {str(e)}")
            continue
        if event_identifiers and event_hash in event_identifiers:
            demisto.info("[CHRONICLE] Skipping insertion of current event since it already exists."
                         f" Event: {event}")
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


def deduplicate_detections(detection_context: list[dict[str, Any]], detection_identifiers: list[dict[str, Any]]):
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
                         f" Detection: {detection}")
            continue
        unique_detections.append(detection)
    return new_detection_identifiers, unique_detections


def deduplicate_curatedrule_detections(detection_context: list[dict[str, Any]],
                                       detection_identifiers: list[dict[str, Any]]):
    """
    De-duplicates the fetched curated rule detections and creates a list of unique detections to be created.

    :type detection_context: Dict[str, Any]
    :param detection_context: Raw response of the detections fetched.
    :type detection_identifiers: List[str]
    :param detection_identifiers: List of dictionaries containing id of detections.

    :rtype: new_detection_identifiers, unique_detections
    :return: Returns updated list of detection identifiers and unique incidents that should be created.
    """
    unique_detections = []
    new_detection_identifiers = []
    for detection in detection_context:
        current_detection_identifier = {'id': detection.get('id', '')}
        new_detection_identifiers.append(current_detection_identifier)
        if detection_identifiers and current_detection_identifier in detection_identifiers:
            demisto.info("[CHRONICLE] Skipping insertion of current detection since it already exists."
                         f" Detection: {detection}")
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


def convert_curatedrule_events_to_actionable_incidents(events: list) -> list:
    """
    Convert event from Curated Rule detection to incident.

    :type events: List
    :param events: List of events.

    :rtype: List
    :return: Returns updated list of detection identifiers and unique incidents that should be created.
    """
    incidents = []
    for event in events:
        event["IncidentType"] = "CuratedRuleDetectionAlert"
        incident = {
            'name': event['detection'][0]['ruleName'],
            'occurred': event.get('detectionTime'),
            'details': json.dumps(event),
            'rawJSON': json.dumps(event),
            'severity': SEVERITY_MAP.get(str(event['detection'][0].get('severity')).lower(), 0)
        }
        incidents.append(incident)

    return incidents


def fetch_detections(client_obj, start_time, end_time, max_fetch, detection_to_process, detection_to_pull,
                     pending_rule_or_version_id: list, alert_state, simple_backoff_rules,
                     fetch_detection_by_list_basis):
    """
    Fetch detections in given time slot.

    This method calls the get_max_fetch_detections method.
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


def fetch_curatedrule_detections(client_obj, start_time, end_time, max_fetch, curatedrule_detection_to_process,
                                 curatedrule_detection_to_pull, pending_curatedrule_id: list, alert_state,
                                 simple_backoff_rules, fetch_detection_by_list_basis):
    """
    Fetch curated rule detections in given time slot.

    This method calls the get_max_fetch_curatedrule_detections method.
    If curated rule detections are more than max_fetch then it partition it into 2 part, from which
    one part(total detection = max_fetch) will be pushed and another part(detection more than max_fetch) will be
    kept in 'curatedrule_detection_to_process' for next cycle. If all rule_id covers, then it will return empty list.

    :type client_obj: Client
    :param client_obj: Client object.
    :type start_time: str
    :param start_time: Start time of request.
    :type end_time: str
    :param end_time: End time of request.
    :type max_fetch: str
    :param max_fetch: Maximum number of incidents to fetch each time.
    :type curatedrule_detection_to_process: List
    :param curatedrule_detection_to_process: List of curated rule detections that were pulled but not processed due to max_fetch.
    :type curatedrule_detection_to_pull: Dict
    :param curatedrule_detection_to_pull: Detections that are larger than max_fetch and had a next page token for fetch incident.
    :type pending_curatedrule_id: str
    :param pending_curatedrule_id: Curated rule id for which detections are yet to be fetched.
    :type alert_state: str
    :param alert_state: Alert state for which detections are yet to be fetched.
    :type simple_backoff_rules: Dict
    :param simple_backoff_rules: max_attempts track for 429 and 500 error.
    :type fetch_detection_by_list_basis: str
    :param fetch_detection_by_list_basis: Sort detections by "DETECTION_TIME" or by "CREATED_TIME".

    :rtype: Tuple[List, List, Dict[str, Any], str, Dict[str, Any]]
    :return: curatedrule_detections, curatedrule_detection_to_process, curatedrule_detection_to_pull,
    pending_curatedrule_id, simple_backoff_rules
    """
    if not pending_curatedrule_id and not curatedrule_detection_to_process and not curatedrule_detection_to_pull \
            and not simple_backoff_rules:
        return [], curatedrule_detection_to_process, curatedrule_detection_to_pull, pending_curatedrule_id, \
            simple_backoff_rules

    # get curated rule detections using API call.
    (curatedrule_detection_to_process, curatedrule_detection_to_pull, pending_curatedrule_id,
     simple_backoff_rules) = get_max_fetch_curatedrule_detections(
        client_obj, start_time, end_time, max_fetch, curatedrule_detection_to_process, curatedrule_detection_to_pull,
        pending_curatedrule_id, alert_state, simple_backoff_rules, fetch_detection_by_list_basis)

    if len(curatedrule_detection_to_process) > max_fetch:
        curatedrule_detections, curatedrule_detection_to_process = curatedrule_detection_to_process[:max_fetch], \
            curatedrule_detection_to_process[max_fetch:]
    else:
        curatedrule_detections = curatedrule_detection_to_process
        curatedrule_detection_to_process = []

    return (curatedrule_detections, curatedrule_detection_to_process, curatedrule_detection_to_pull,
            pending_curatedrule_id, simple_backoff_rules)


def get_max_fetch_detections(client_obj, start_time, end_time, max_fetch, detection_incidents, detection_to_pull,
                             pending_rule_or_version_id, alert_state, simple_backoff_rules,
                             fetch_detection_by_list_basis):
    """
    Get list of detection using detection_to_pull and pending_rule_or_version_id.

    If the API responds with 429, 500 error then it will retry it for 60 times(each attempt take one minute).
    If it responds with 400 or 404 error, then it will skip that rule_id. In case of an empty response for any next_page_token
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
            if str(e).startswith('API rate limit') or str(e).startswith('Internal server error'):
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

        detections: list[dict[str, Any]] = raw_resp.get('detections', [])

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


def get_max_fetch_curatedrule_detections(client_obj, start_time, end_time, max_fetch, curatedrule_detection_to_process,
                                         curatedrule_detection_to_pull, pending_curatedrule_id, alert_state,
                                         simple_backoff_rules, fetch_detection_by_list_basis):
    """
    Get list of curated rule detection using curatedrule_detection_to_pull and pending_curatedrule_id.

    If the API responds with 429, 500 error then it will retry it for 60 times(each attempt take one minute).
    If it responds with 400 or 404 error, then it will skip that curatedrule_id. In case of an empty response for any
    next_page_token, it will skip that curatedrule_id.

    :type client_obj: Client
    :param client_obj: Client object.
    :type start_time: str
    :param start_time: Start time of request.
    :type end_time: str
    :param end_time: End time of request.
    :type max_fetch: str
    :param max_fetch: Maximum number of incidents to fetch each time.
    :type curatedrule_detection_to_process: List
    :param curatedrule_detection_to_process: List of curated rule detections that were pulled but not processed due to max_fetch.
    :type curatedrule_detection_to_pull: Dict
    :param curatedrule_detection_to_pull: Detections that are larger than max_fetch and had a next page token for fetch incident.
    :type pending_curatedrule_id: str
    :param pending_curatedrule_id: Curated rule id for which detections are yet to be fetched.
    :type alert_state: str
    :param alert_state: Alert state for which detections are yet to be fetched.
    :type simple_backoff_rules: Dict
    :param simple_backoff_rules: max_attempts track for 429 and 500 error.
    :type fetch_detection_by_list_basis: str
    :param fetch_detection_by_list_basis: Sort detections by "DETECTION_TIME" or by "CREATED_TIME".

    :rtype: Tuple[List, Dict[str, Any], str, Dict[str, Any]]
    :return: curatedrule_detection_to_process, curatedrule_detection_to_pull, pending_curatedrule_id, simple_backoff_rules
    """
    # loop if length of detection is less than max_fetch and if any further rule_id(with or without next_page_token)
    # or any retry attempt remaining
    while len(curatedrule_detection_to_process) < max_fetch and (
            len(pending_curatedrule_id) != 0 or curatedrule_detection_to_pull or simple_backoff_rules):

        next_page_token = ''
        if curatedrule_detection_to_pull:
            rule_id = curatedrule_detection_to_pull.get('rule_id')
            next_page_token = curatedrule_detection_to_pull.get('next_page_token')
        elif simple_backoff_rules:
            rule_id = simple_backoff_rules.get('rule_id')
            next_page_token = simple_backoff_rules.get('next_page_token')
        else:
            rule_id = pending_curatedrule_id.pop(0)
        try:
            _, raw_resp = get_curatedrule_detections(client_obj, rule_id, max_fetch, start_time, end_time,
                                                     next_page_token, alert_state,
                                                     list_basis=fetch_detection_by_list_basis)
        except ValueError as e:
            if str(e).startswith('API rate limit') or str(e).startswith('Internal server error'):
                attempts = simple_backoff_rules.get('attempts', 0)
                if attempts < MAX_ATTEMPTS:
                    demisto.error(
                        f"[CHRONICLE CURATED RULE DETECTIONS] Error while fetching incidents: {str(e)} Attempt no : "
                        f"{attempts + 1} for the curated rule_id : {rule_id} and next_page_token : {next_page_token}")
                    simple_backoff_rules = {'rule_id': rule_id, 'next_page_token': next_page_token,
                                            'attempts': attempts + 1}
                else:
                    demisto.error(f"[CHRONICLE CURATED RULE DETECTIONS] Skipping the rule_id : {rule_id} "
                                  f"due to the maximum number of attempts ({MAX_ATTEMPTS}). "
                                  "You'll experience data loss for the given curated rule_id. "
                                  f"Switching to next curated rule_id.")
                    simple_backoff_rules = {}
                    curatedrule_detection_to_pull = {}
                break

            if str(e).startswith('Status code: 404') or str(e).startswith('Status code: 400'):
                if str(e).startswith('Status code: 404'):
                    demisto.error("[CHRONICLE CURATED RULE DETECTIONS] Error while fetching incidents: Rule with ID"
                                  f" {rule_id} not found.")
                else:
                    demisto.error("[CHRONICLE CURATED RULE DETECTIONS] Error while fetching incidents: Rule with ID"
                                  f" {rule_id} is invalid.")
                curatedrule_detection_to_pull = {}
                simple_backoff_rules = {}
                break

            demisto.error("Error while fetching incidents: " + str(e))
            if not curatedrule_detection_to_pull:
                pending_curatedrule_id.insert(0, rule_id)

            break

        if not raw_resp:
            curatedrule_detection_to_pull = {}
            simple_backoff_rules = {}
            continue

        curatedrule_detections: list[dict[str, Any]] = raw_resp.get('curatedRuleDetections', [])

        # Add found detection in incident list.
        add_curatedrule_detections_in_incident_list(curatedrule_detections, curatedrule_detection_to_process)

        if raw_resp.get('nextPageToken'):
            next_page_token = str(raw_resp.get('nextPageToken'))
            curatedrule_detection_to_pull = {'rule_id': rule_id, 'next_page_token': next_page_token}
            simple_backoff_rules = {'rule_id': rule_id, 'next_page_token': next_page_token}

        # when exact size is returned but no next_page_token
        if len(curatedrule_detections) <= max_fetch and not raw_resp.get('nextPageToken'):
            curatedrule_detection_to_pull = {}
            simple_backoff_rules = {}

    return curatedrule_detection_to_process, curatedrule_detection_to_pull, pending_curatedrule_id, simple_backoff_rules


def add_detections_in_incident_list(detections: list, detection_incidents: list) -> None:
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


def add_curatedrule_detections_in_incident_list(curatedrule_detections: list,
                                                curatedrule_detection_to_process: list) -> None:
    """
    Add found detection in incident list.

    :type curatedrule_detections: List
    :param curatedrule_detections: List of curated detection.
    :type curatedrule_detection_to_process: List
    :param curatedrule_detection_to_process: List of incidents.

    :rtype: None
    """
    if curatedrule_detections and len(curatedrule_detections) > 0:
        for detection in curatedrule_detections:
            events_ec = get_events_context_for_curatedrule_detections(detection.get('collectionElements', []))
            detection['collectionElements'] = events_ec
        curatedrule_detection_to_process.extend(curatedrule_detections)


def get_unique_value_from_list(data: list) -> list:
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


def fetch_incidents_asset_alerts(client_obj, params: dict[str, Any], start_time, end_time, time_window, max_fetch):
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
    assets_alerts_identifiers: list = []
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


def fetch_incidents_user_alerts(client_obj, params: dict[str, Any], start_time, end_time, time_window, max_fetch):
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
    user_alerts_identifiers: list = []
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


def fetch_incidents_detection_alerts(client_obj, params: dict[str, Any], start_time, end_time, time_window, max_fetch):
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
    detection_to_process: list[dict[str, Any]] = []
    # detections that are larger than max_fetch and had a next page token for fetch incident.
    detection_to_pull: dict[str, Any] = {}
    # max_attempts track for 429 and 500 error
    simple_backoff_rules: dict[str, Any] = {}
    # rule_id or version_id and alert_state for which detections are yet to be fetched.
    pending_rule_or_version_id_with_alert_state: dict[str, Any] = {}
    detection_identifiers: list = []
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

    if params.get('fetch_detection_by_list_basis') == 'DETECTION_TIME':
        delayed_start_time = generate_delayed_start_time(time_window, start_time)
    else:
        delayed_start_time = start_time

    fetch_detection_by_alert_state = pending_rule_or_version_id_with_alert_state.get('alert_state', '')
    fetch_detection_by_list_basis = pending_rule_or_version_id_with_alert_state.get('listBasis', 'CREATED_TIME')
    # giving priority to comma separated detection ids over check box of fetch all live detections
    if not pending_rule_or_version_id_with_alert_state.get("rule_id") and \
            not detection_to_pull and not detection_to_process and not simple_backoff_rules:
        fetch_detection_by_ids = params.get('fetch_detection_by_ids') or ""
        if not fetch_detection_by_ids and params.get('fetch_all_detections', False):
            fetch_detection_by_ids = '-'
        fetch_detection_by_ids = get_unique_value_from_list(
            [r_v_id.strip() for r_v_id in fetch_detection_by_ids.split(',')])

        fetch_detection_by_alert_state = params.get('fetch_detection_by_alert_state',
                                                    fetch_detection_by_alert_state)
        fetch_detection_by_list_basis = params.get('fetch_detection_by_list_basis', fetch_detection_by_list_basis)

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


def fetch_incidents_curatedrule_detection_alerts(client_obj, params: dict[str, Any], start_time, end_time, time_window,
                                                 max_fetch):
    """Fetch incidents of curated rule detection alert type.

    :type client_obj: Client
    :param client_obj: Client object.
    :type params: Dict
    :param params: Configuration parameter of fetch incidents.
    :type start_time: str
    :param start_time: Start time of request.
    :type end_time: str
    :param end_time: End time of request.
    :type time_window: str
    :param time_window: Time delay for an event to appear in chronicle after generation.
    :type max_fetch: str
    :param max_fetch: Maximum number of incidents to fetch each time.

    :rtype: List
    :return: List of incidents.
    """
    # list of curated rule detections that were pulled but not processed due to max_fetch.
    curatedrule_detection_to_process: list[dict[str, Any]] = []
    # curated rule detections that are larger than max_fetch and had a next page token for fetch incident.
    curatedrule_detection_to_pull: dict[str, Any] = {}
    # max_attempts track for 429 and 500 error.
    simple_backoff_curatedrules: dict[str, Any] = {}
    # curated rule_id and alert_state for which detections are yet to be fetched.
    pending_curatedrule_id_with_alert_state: dict[str, Any] = {}
    curatedrule_detection_identifiers: list = []
    curatedrule_first_fetched_time = None

    last_run = demisto.getLastRun()
    incidents = []

    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time') or start_time
        curatedrule_detection_identifiers = last_run.get('curatedrule_detection_identifiers',
                                                         curatedrule_detection_identifiers)
        curatedrule_detection_to_process = last_run.get('curatedrule_detection_to_process',
                                                        curatedrule_detection_to_process)
        curatedrule_detection_to_pull = last_run.get('curatedrule_detection_to_pull', curatedrule_detection_to_pull)
        simple_backoff_curatedrules = last_run.get('simple_backoff_curatedrules', simple_backoff_curatedrules)
        pending_curatedrule_id_with_alert_state = last_run.get('pending_curatedrule_id_with_alert_state',
                                                               pending_curatedrule_id_with_alert_state)
        end_time = last_run.get('curatedrule_first_fetched_time') or end_time

    if params.get('fetch_detection_by_list_basis') == 'DETECTION_TIME':
        delayed_start_time = generate_delayed_start_time(time_window, start_time)
    else:
        delayed_start_time = start_time

    if not last_run.get('curatedrule_first_fetched_time'):
        demisto.info("[CHRONICLE CURATED RULE DETECTIONS] Starting new time window from START-TIME :"
                     f" {delayed_start_time} to END_TIME : {end_time}")

    fetch_detection_by_alert_state = pending_curatedrule_id_with_alert_state.get('alert_state', '')
    fetch_detection_by_list_basis = pending_curatedrule_id_with_alert_state.get('listBasis', 'CREATED_TIME')
    # giving priority to comma separated detection ids over check box of fetch all live detections
    if not pending_curatedrule_id_with_alert_state.get("rule_id") and not curatedrule_detection_to_pull and \
            not curatedrule_detection_to_process and not simple_backoff_curatedrules:
        fetch_detection_by_ids = params.get('fetch_detection_by_ids') or ""
        if not fetch_detection_by_ids:
            raise ValueError(MESSAGES['PROVIDE_CURATED_RULE_ID'])
        fetch_detection_by_ids = get_unique_value_from_list(
            [r_v_id.strip() for r_v_id in fetch_detection_by_ids.split(',')])

        fetch_detection_by_alert_state = params.get('fetch_detection_by_alert_state',
                                                    fetch_detection_by_alert_state)
        fetch_detection_by_list_basis = params.get('fetch_detection_by_list_basis', fetch_detection_by_list_basis)

        # when 1st time fetch or when pending_curatedrule_id got emptied in last sync.
        # when curatedrule_detection_to_pull has some rule ids
        pending_curatedrule_id_with_alert_state.update({'rule_id': fetch_detection_by_ids,
                                                        'alert_state': fetch_detection_by_alert_state,
                                                        'listBasis': fetch_detection_by_list_basis})

    (curatedrule_detections, curatedrule_detection_to_process, curatedrule_detection_to_pull, pending_curatedrule_id,
     simple_backoff_curatedrules) = fetch_curatedrule_detections(
        client_obj, delayed_start_time, end_time, int(max_fetch), curatedrule_detection_to_process,
        curatedrule_detection_to_pull, pending_curatedrule_id_with_alert_state.get('rule_id', ''),
        pending_curatedrule_id_with_alert_state.get('alert_state', ''), simple_backoff_curatedrules,
        pending_curatedrule_id_with_alert_state.get('listBasis'))

    # The batch processing is in progress i.e. detections for pending rules are yet to be fetched
    # so updating the end_time to the start time when considered for current batch
    if pending_curatedrule_id or curatedrule_detection_to_pull or simple_backoff_curatedrules:
        curatedrule_first_fetched_time = end_time
        end_time = start_time
    else:
        demisto.info("[CHRONICLE CURATED RULE DETECTIONS] End of current time window from START-TIME :"
                     f" {start_time} to END_TIME : {end_time}")

    pending_curatedrule_id_with_alert_state.update({'rule_id': pending_curatedrule_id,
                                                    'alert_state': fetch_detection_by_alert_state,
                                                    'listBasis': fetch_detection_by_list_basis})

    curatedrule_detection_identifiers, unique_detections = deduplicate_curatedrule_detections(
        curatedrule_detections, curatedrule_detection_identifiers)

    if unique_detections:
        incidents = convert_curatedrule_events_to_actionable_incidents(unique_detections)

    demisto.setLastRun({
        'start_time': end_time,
        'curatedrule_detection_identifiers': curatedrule_detection_identifiers,
        'curatedrule_first_fetched_time': curatedrule_first_fetched_time,
        'curatedrule_detection_to_process': curatedrule_detection_to_process,
        'curatedrule_detection_to_pull': curatedrule_detection_to_pull,
        'simple_backoff_curatedrules': simple_backoff_curatedrules,
        'pending_curatedrule_id_with_alert_state': pending_curatedrule_id_with_alert_state
    })

    return incidents


def convert_events_to_chronicle_event_incident_field(events: list) -> None:
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
    request_url = f'{BACKSTORY_API_V1_URL}/alert/listalerts?start_time={start_time}&end_time={end_time}&page_size={max_fetch}'
    demisto.debug(f"[CHRONICLE] Request URL for fetching user alerts: {request_url}")

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
    Group user alerts with combination of user identifier and alert name.

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
            ALERT_NAMES: value[0].get("Name", ""),
            FIRST_SEEN: get_informal_time(occurrences[0]),
            LAST_SEEN: get_informal_time(occurrences[-1]),
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
        hr += MESSAGES["NO_RECORDS"]
        return hr, {}, {}

    # prepare alerts into human readable
    data, _ = group_infos_by_alert_user_name(alerts)
    hr = tableToMarkdown('User Alert(s)', data, ['Alerts', 'User', ALERT_NAMES, FIRST_SEEN, LAST_SEEN, 'Sources'],
                         removeNull=True)

    for alert in alerts:
        for alert_info in alert.get('AlertInfo', []):
            alert_info.pop('Uri', None)
            alert_info.pop('UdmEvent', None)

    ec = {
        CHRONICLE_OUTPUT_PATHS['UserAlert']: alerts
    }

    return hr, ec, alerts


def get_context_for_rules(rule_resp: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Convert rules response into Context data.

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


def get_rules(client_obj, args: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-list-rules command.

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
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))

    live_rule = args.get('live_rule', '').lower()
    if live_rule and live_rule != 'true' and live_rule != 'false':
        raise ValueError('Live rule should be true or false.')

    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules?pageSize={page_size}'

    # Append parameters if specified
    if page_token:
        request_url += f'&page_token={page_token}'

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
    ec: dict[str, Any] = {
        CHRONICLE_OUTPUT_PATHS['Rules']: parsed_ec
    }
    if token_ec:
        ec.update({CHRONICLE_OUTPUT_PATHS['Token']: token_ec})
    return ec, raw_resp


def get_list_rules_hr(rules: list[dict[str, Any]]) -> str:
    """
    Convert rules response into human readable.

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


def validate_rule_text(rule_text: str):
    """
    Validate the rule text.

    :type rule_text: str
    :param rule_text: the rule text
    """
    validate_argument(value=rule_text, name='rule_text')

    if 'meta' not in rule_text or 'events' not in rule_text or 'condition' not in rule_text:
        raise ValueError(MESSAGES['INVALID_RULE_TEXT'])


def create_rule(client_obj, rule_text: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-create-rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_text: str
    :param rule_text: the rule text to for the rule to be created

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the created rule
    """
    req_json_data = {
        'ruleText': rule_text
    }
    request_url = f"{BACKSTORY_API_V2_URL}/detect/rules"
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(req_json_data))

    ec = {
        CHRONICLE_OUTPUT_PATHS['Rules']: json_data
    }

    return ec, json_data


def prepare_hr_for_create_rule(rule_details: dict[str, Any]) -> str:
    """
    Prepare human-readable for create rule command.

    :type rule_details: Dict[str, Any]
    :param rule_details: Response of create rule

    :rtype: str
    :return: Human readable string for create rule command
    """
    hr_output = {
        'Rule ID': rule_details.get('ruleId'),
        'Version ID': rule_details.get('versionId'),
        'Author': rule_details.get('metadata', {}).get('author'),
        'Rule Name': rule_details.get('ruleName'),
        'Description': rule_details.get('metadata', {}).get('description'),
        'Version Creation Time': rule_details.get('versionCreateTime'),
        'Compilation Status': rule_details.get('compilationState'),
        'Rule Text': rule_details.get('ruleText')
    }

    headers = ['Rule ID', 'Version ID', 'Author', 'Rule Name', 'Description', 'Version Creation Time',
               'Compilation Status', 'Rule Text']

    return tableToMarkdown('Rule Detail', hr_output, headers=headers, removeNull=True)


def gcb_get_rule(client_obj, rule_id):
    """
    Return context data and raw response for gcb-get-rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the fetched rules
    """
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}'
    json_data = validate_response(client_obj, request_url)
    ec = {
        CHRONICLE_OUTPUT_PATHS['Rules']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_get_rule_command(json_data):
    """
    Prepare Human Readable output from the response received.

    :type json_data: Dict
    :param json_data: raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    hr_output = {
        'Rule ID': json_data.get('ruleId'),
        'Version ID': json_data.get('versionId'),
        'Author': json_data.get('metadata', {}).get('author'),
        'Rule Name': json_data.get('ruleName'),
        'Description': json_data.get('metadata', {}).get('description'),
        'Version Creation Time': json_data.get('versionCreateTime'),
        'Compilation Status': json_data.get('compilationState'),
        'Rule Text': json_data.get('ruleText')
    }
    hr = tableToMarkdown('Rule Details', hr_output,
                         headers=['Rule ID', 'Version ID', 'Author', 'Rule Name', 'Description',
                                  'Version Creation Time', 'Compilation Status', 'Rule Text'], removeNull=True)
    return hr


def delete_rule(client_obj, rule_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-delete-rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: rule id of the rule to be deleted

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the created rule
    """
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}'
    json_data = validate_response(client_obj, request_url, method='DELETE')

    json_data = {
        'ruleId': rule_id,
        'actionStatus': 'SUCCESS' if not json_data else 'FAILURE'
    }

    ec = {
        CHRONICLE_OUTPUT_PATHS['DeleteRule']: json_data
    }

    return ec, json_data


def prepare_hr_for_delete_rule(response: dict[str, str]) -> str:
    """
    Prepare human-readable for create rule command.

    :type response: Dict[str, Any]
    :param response: Response of create rule

    :rtype: str
    :return: Human readable string for create rule command
    """
    hr_output = {
        'Rule ID': response.get('ruleId'),
        'Action Status': response.get('actionStatus')
    }

    if response.get('actionStatus') == 'SUCCESS':
        title = f'Rule with ID {response.get("ruleId")} deleted successfully.'
    else:
        title = f'Could not delete the rule with ID {response.get("ruleId")}.'

    return tableToMarkdown(title, hr_output, headers=['Rule ID', 'Action Status'], removeNull=True)


def gcb_create_rule_version(client_obj, rule_id, rule_text):
    """
    Return context data and raw response for gcb-create-rule-version command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId

    :type rule_text: str
    :param rule_text: it is the rule itself to add.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}:createVersion'
    body = {
        "ruleText": rule_text
    }
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(body))
    json_data = remove_empty_elements(json_data)
    ec = {
        CHRONICLE_OUTPUT_PATHS['Rules']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_create_rule_version_command(json_data):
    """
    Prepare human-readable for gcb_create_rule_version_command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb_create_rule_version_command

    :rtype: str
    :return: Human readable string for gcb_create_rule_version_command
    """
    hr_output = {
        'Rule ID': json_data.get('ruleId'),
        'Version ID': json_data.get('versionId'),
        'Author': json_data.get('metadata', {}).get('author'),
        'Rule Name': json_data.get('ruleName'),
        'Description': json_data.get('metadata', {}).get('description'),
        'Version Creation Time': json_data.get('versionCreateTime'),
        'Compilation Status': json_data.get('compilationState'),
        'Rule Text': json_data.get('ruleText')
    }
    hr = tableToMarkdown('New Rule Version Details', hr_output,
                         headers=['Rule ID', 'Version ID', 'Author', 'Rule Name', 'Description',
                                  'Version Creation Time', 'Compilation Status', 'Rule Text'], removeNull=True)
    return hr


def gcb_change_rule_alerting_status(client_obj, rule_id, alerting_status):
    """
    Return context data and raw response for gcb-change-rule-alerting-status command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: the ruleId of the rule whose alerting status is to be updated.

    :type alerting_status: str
    :param alerting_status: indicates whether to enable or disable the alerting stats for the rule.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the update in alerting status of the rule
    """
    alert_status = 'enableAlerting' if alerting_status == 'enable' else 'disableAlerting'
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}:{alert_status}'
    json_data = validate_response(client_obj, request_url, method='POST')
    json_data = {
        'ruleId': rule_id,
        'actionStatus': 'SUCCESS' if not json_data else 'FAILURE',
        'alertingStatus': alerting_status
    }
    ec = {
        CHRONICLE_OUTPUT_PATHS['RuleAlertingChange']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_change_rule_alerting_status(json_data, alerting_status):
    """
    Prepare human-readable for gcb-change-rule-alerting-status command.

    :type json_data: Dict
    :param json_data: raw response received from api in json format.

    :type alerting_status: str
    :param alerting_status: status value to be updated.

    :return: Human Readable output to display.
    :rtype: str
    """
    status = 'enabled' if alerting_status == 'enable' else 'disabled'
    hr_output = {
        'Rule ID': json_data.get('ruleId'),
        'Action Status': json_data.get('actionStatus')
    }
    hr = tableToMarkdown('Alerting Status', hr_output, headers=['Rule ID', 'Action Status'], removeNull=True,
                         metadata=MESSAGES['CHANGE_RULE_ALERTING_METADATA'].format(json_data.get('ruleId'), status))
    return hr


def gcb_change_live_rule_status(client_obj, rule_id, live_rule_status):
    """
    Return context data and raw response for gcb-change-live-rule-status command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId

    :type live_rule_status: str
    :param live_rule_status: new status of the rule to be changed

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    if live_rule_status == 'enable':
        request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}:enableLiveRule'
    else:
        request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}:disableLiveRule'

    json_data = validate_response(client_obj, request_url, method='POST')

    json_data = {
        'ruleId': rule_id,
        'actionStatus': 'SUCCESS' if not json_data else 'FAILED',
        'liveRuleStatus': live_rule_status
    }

    ec = {
        CHRONICLE_OUTPUT_PATHS['LiveRuleStatusChange']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_change_live_rule_status_command(json_data, live_rule_status):
    """
    Prepare human-readable for gcb-change-live-rule-status-command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-change-live-rule-status-command

    :type live_rule_status: str
    :param live_rule_status: status value to be changed

    :rtype: str
    :return: Human readable string for gcb-change-live-rule-status-command
    """
    hr_output = {
        'Rule ID': json_data.get('ruleId'),
        'Action Status': json_data.get('actionStatus')
    }
    status = 'enabled' if live_rule_status == 'enable' else 'disabled'
    hr = tableToMarkdown('Live Rule Status', hr_output,
                         headers=['Rule ID', 'Action Status'], removeNull=True,
                         metadata=MESSAGES['CHANGE_LIVE_RULE_STATUS_METADATA'].format(json_data.get('ruleId'), status))

    return hr


def gcb_start_retrohunt(client_obj, rule_id, start_time, end_time):
    """
    Return context data and raw response for gcb-start-retrohunt command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId

    :type start_time: str
    :param start_time: start time for the time range of logs being processed

    :type end_time: str
    :param end_time: end time for the time range of logs being processed.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}:runRetrohunt'
    body = {
        "start_time": start_time,
        "end_time": end_time
    }
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(body))
    ec = {
        CHRONICLE_OUTPUT_PATHS['RetroHunt']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_start_retrohunt_command(json_data):
    """
    Prepare human-readable for gcb-start-retrohunt command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-start-retrohunt command

    :rtype: str
    :return: Human readable string for gcb-start-retrohunt command
    """
    hr_output = {
        "Retrohunt ID": json_data.get('retrohuntId'),
        "Rule ID": json_data.get('ruleId'),
        "Version ID": json_data.get('versionId'),
        "Event Start Time": json_data.get('eventStartTime'),
        "Event End Time": json_data.get('eventEndTime'),
        "Retrohunt Start Time": json_data.get('retrohuntStartTime'),
        "State": json_data.get('state')
    }

    hr = tableToMarkdown('Retrohunt Details', hr_output,
                         headers=['Retrohunt ID', 'Rule ID', 'Version ID', 'Event Start Time',
                                  'Event End Time', 'Retrohunt Start Time', 'State'],
                         removeNull=True)
    return hr


def gcb_list_retrohunts(client_obj, rule_id, retrohunts_for_all_versions, state, page_size, page_token):
    """
    Return context data and raw response for gcb-list-retrohunts command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId

    :type retrohunts_for_all_versions: bool
    :param retrohunts_for_all_versions: bool value to create list for all retrohunt of the rule id provided

    :type state: str
    :param state: it is the state of the retrohunt to include in list

    :type page_size: int
    :param page_size: it indicates the no of output entries to display

    :type page_token: str
    :param page_token: it is the base64 page token for next page of the outputs

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    encoded_params = urllib.parse.urlencode(assign_params(page_size=page_size, page_token=page_token, state=state))
    if retrohunts_for_all_versions and rule_id:
        request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}@-/retrohunts?{encoded_params}'
    elif rule_id:
        request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_id}/retrohunts?{encoded_params}'
    else:
        request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/-/retrohunts?{encoded_params}'

    json_data = validate_response(client_obj, request_url)
    ec = {
        CHRONICLE_OUTPUT_PATHS['RetroHunt']: json_data.get('retrohunts')
    }
    return ec, json_data


def prepare_hr_for_gcb_list_retrohunts_commands(json_data):
    """
    Prepare human-readable for gcb-list-retrohunts.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-list-retrohunts

    :rtype: str
    :return: Human readable string for gcb-list-retrohunts
    """
    next_page_token = json_data.get('nextPageToken')
    json_data = json_data.get('retrohunts')
    hr_output = []
    for output in json_data:
        hr_output.append({
            'Retrohunt ID': output.get('retrohuntId'),
            'Rule ID': output.get('ruleId'),
            'Version ID': output.get('versionId'),
            'Event Start Time': output.get('eventStartTime'),
            'Event End Time': output.get('eventEndTime'),
            'Retrohunt Start Time': output.get('retrohuntStartTime'),
            'Retrohunt End Time': output.get('retrohuntEndTime'),
            'State': output.get('state'),
            'Progress Percentage': output.get('progressPercentage')
        })
    hr = tableToMarkdown('Retrohunt Details', hr_output,
                         headers=['Retrohunt ID', 'Rule ID', 'Version ID', 'Event Start Time', 'Event End Time',
                                  'Retrohunt Start Time', 'Retrohunt End Time', 'State', 'Progress Percentage'],
                         removeNull=True)
    if next_page_token:
        hr += '\nMaximum number of retrohunts specified in page_size has been returned. To fetch the next set of' \
              f' retrohunts, execute the command with the page token as {next_page_token}'
    return hr


def gcb_get_retrohunt(client_obj, rule_or_version_id, retrohunt_id):
    """
    Return context data and raw response for gcb-get-retrohunt command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_or_version_id: str
    :param rule_or_version_id: Rule ID or Version ID of the rule whose retrohunts are to be listed.

    :type retrohunt_id: str
    :param retrohunt_id: Unique identifier for a retrohunt, defined and returned by the server.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the created rule
    """
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_or_version_id}/retrohunts/{retrohunt_id}'
    json_data = validate_response(client_obj, request_url)

    ec = {
        CHRONICLE_OUTPUT_PATHS['RetroHunt']: json_data
    }

    return ec, json_data


def prepare_hr_for_get_retrohunt(retrohunt_details: dict[str, Any]) -> str:
    """
    Prepare human-readable for get-retrohunt command.

    :type retrohunt_details: Dict[str, Any]
    :param retrohunt_details: Response of get retrohunt

    :rtype: str
    :return: Human readable string for get-retrohunt command
    """
    hr_output = {
        'Retrohunt ID': retrohunt_details.get('retrohuntId'),
        'Rule ID': retrohunt_details.get('ruleId'),
        'Version ID': retrohunt_details.get('versionId'),
        'Event Start Time': retrohunt_details.get('eventStartTime'),
        'Event End Time': retrohunt_details.get('eventEndTime'),
        'Retrohunt Start Time': retrohunt_details.get('retrohuntStartTime'),
        'Retrohunt End Time': retrohunt_details.get('retrohuntEndTime'),
        'State': retrohunt_details.get('state'),
        'Progress Percentage': retrohunt_details.get('progressPercentage')
    }

    headers = ['Retrohunt ID', 'Rule ID', 'Version ID', 'Event Start Time', 'Event End Time', 'Retrohunt Start Time',
               'Retrohunt End Time', 'State', 'Progress Percentage']

    return tableToMarkdown('Retrohunt Details', hr_output, headers=headers, removeNull=True)


def gcb_cancel_retrohunt(client_obj, rule_or_version_id, retrohunt_id):
    """
    Return context data and raw response for gcb-cancel-retrohunt command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_or_version_id: str
    :param rule_or_version_id: it is the ruleId or versionId

    :type retrohunt_id: str
    :param retrohunt_id: it is the unique id of the retrohunt

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    request_url = f'{BACKSTORY_API_V2_URL}/detect/rules/{rule_or_version_id}/retrohunts/{retrohunt_id}:cancelRetrohunt'
    json_data = validate_response(client_obj, request_url, method='POST')
    json_data = {
        'id': rule_or_version_id,
        'retrohuntId': retrohunt_id,
        'cancelled': bool(not json_data),
    }
    ec = {
        CHRONICLE_OUTPUT_PATHS['RetroHunt']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_cancel_retrohunt(json_data):
    """
    Prepare human-readable for gcb-cancel-retrohunt command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of get cb-cancel-retrohunt

    :rtype: str
    :return: Human readable string for gcb-cancel-retrohunt command
    """
    hr_output = {
        'ID': json_data.get('id'),
        'Retrohunt ID': json_data.get('retrohuntId'),
        'Action Status': 'SUCCESS' if json_data.get('cancelled') else 'FAILURE'
    }
    hr = tableToMarkdown('Cancelled Retrohunt', hr_output, headers=['ID', 'Retrohunt ID', 'Action Status'],
                         removeNull=True,
                         metadata=MESSAGES['CANCEL_RETROHUNT'].format(json_data.get('id')))
    return hr


def gcb_create_reference_list(client_obj, name, description, lines, content_type):
    """
    Return context data and raw response for gcb_create_reference_list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type name: str
    :param name: the name of the list to create

    :type description: str
    :param description: description of the list to create

    :type lines: list
    :param lines: items to put in the list

    :type content_type: str
    :param content_type: the content_type of lines

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    content_type = 'CONTENT_TYPE_DEFAULT_STRING' if content_type == DEFAULT_CONTENT_TYPE else content_type
    body = {
        "name": name,
        "description": description,
        "lines": lines,
        "content_type": content_type,
    }
    request_url = f'{BACKSTORY_API_V2_URL}/lists'
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(body))
    json_data['contentType'] = json_data.get('contentType', DEFAULT_CONTENT_TYPE)
    ec = {
        CHRONICLE_OUTPUT_PATHS['ReferenceList']: json_data
    }
    return ec, json_data


def prepare_hr_for_gcb_create_get_update_reference_list(json_data, table_name='Reference List Details'):
    """
    Prepare human-readable for gcb_create_reference_list, gcb_get_reference_list, gcb_update_reference_list command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of the command

    :type table_name: str
    :param table_name: Name of the table to display

    :rtype: str
    :return: Human readable string for the command
    """
    hr_output = {
        'Name': json_data.get('name'),
        'Description': json_data.get('description'),
        'Creation Time': json_data.get('createTime'),
        'Content Type': json_data.get('contentType'),
        'Content': string_escape_markdown(json_data.get('lines'))
    }

    headers = ['Name', 'Content Type', 'Description', 'Creation Time', 'Content']

    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def gcb_list_reference_list(client_obj, page_size, page_token, view):
    """
    Return context data and raw response for gcb-list-reference-list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type page_size: int
    :param page_size: it indicates the no. of output entries to display

    :type page_token: str
    :param page_token: it is the base64 page token for next page of the outputs

    :type view: str
    :param view: it is the view type of the lists to be displayed

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    encoded_params = urllib.parse.urlencode(assign_params(page_size=page_size, page_token=page_token, view=view))

    request_url = f'{BACKSTORY_API_V2_URL}/lists?{encoded_params}'

    json_data = validate_response(client_obj, request_url, method='GET')
    references_list = json_data.get('lists')
    for reference in references_list:
        reference['contentType'] = reference.get('contentType', DEFAULT_CONTENT_TYPE)
    ec = {
        CHRONICLE_OUTPUT_PATHS['ListReferenceList']: references_list
    }
    return ec, json_data


def prepare_hr_for_gcb_list_reference_list(json_data):
    """
    Prepare human-readable for gcb-list-reference-list.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-list-reference-list

    :rtype: str
    :return: Human readable string for gcb-list-reference-list
    """
    page_token = json_data.get('nextPageToken')
    json_data = json_data.get('lists')
    hr_output = []
    for output in json_data:
        hr_output.append({
            'Name': output.get('name'),
            'Creation Time': output.get('createTime'),
            'Description': output.get('description'),
            'Content Type': output.get('contentType'),
            'Content': string_escape_markdown(output.get('lines'))
        })
    hr = tableToMarkdown('Reference List Details', hr_output,
                         headers=['Name', 'Content Type', 'Creation Time', 'Description', 'Content'], removeNull=True)
    if page_token:
        hr += '\nMaximum number of reference lists specified in page_size has been returned. To fetch the next set of' \
              f' lists, execute the command with the page token as {page_token}'
    return hr


def gcb_get_reference_list(client_obj, name, view):
    """
    Return context data and raw response for gcb-get-reference-list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type name: str
    :param name: Unique name of the reference list

    :type view: str
    :param view: it is the view type of the lists to be displayed

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    encoded_params = urllib.parse.urlencode(assign_params(view=view))
    request_url = f'{BACKSTORY_API_V2_URL}/lists/{name}?{encoded_params}'
    json_data = validate_response(client_obj, request_url, method='GET')
    json_data['contentType'] = json_data.get('contentType', DEFAULT_CONTENT_TYPE)
    ec = {
        CHRONICLE_OUTPUT_PATHS['ReferenceList']: json_data
    }
    return ec, json_data


def gcb_update_reference_list(client_obj, name, lines, description, content_type):
    """
    Return context data and raw response for gcb_update_reference_list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type name: str
    :param name: the name of the list to create

    :type description: str
    :param description: description of the list to create

    :type lines: list
    :param lines: items to put in the list

    :type content_type: str
    :param content_type: the content_type of lines

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    request_url = f'{BACKSTORY_API_V2_URL}/lists?update_mask=list.lines'
    content_type = 'CONTENT_TYPE_DEFAULT_STRING' if content_type == DEFAULT_CONTENT_TYPE else content_type
    body = {
        "name": name,
        "lines": lines,
        "description": description,
        "content_type": content_type,
    }
    if description:
        request_url += ',list.description'
        # body["description"] = description
    json_data = validate_response(client_obj, request_url, method='PATCH', body=json.dumps(body))
    json_data['contentType'] = json_data.get('contentType', DEFAULT_CONTENT_TYPE)
    ec = {
        CHRONICLE_OUTPUT_PATHS['ReferenceList']: json_data
    }
    return ec, json_data


def prepare_hr_for_verify_reference_list(json_data, content_type):
    """
    Prepare human-readable for gcb-verify-reference-list.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-verify-reference-list

    :type content_type: str
    :param content_type: the content_type of lines

    :rtype: str
    :return: Human readable string for gcb-verify-reference-list
    """
    success = json_data.get('success', False)
    if success:
        return '### All provided lines meet validation criteria.'
    json_data = json_data.get('errors', [])
    hr_output = []
    for output in json_data:
        hr_output.append({
            'Line Number': output.get('lineNumber'),
            'Message': string_escape_markdown(output.get('errorMessage')),
        })
    hr = tableToMarkdown(f'The following lines contain invalid {content_type} pattern.', hr_output,
                         headers=['Line Number', 'Message'], removeNull=True)
    return hr


def gcb_verify_reference_list(client_obj, lines, content_type):
    """
    Return context data and raw response for gcb_verify_reference_list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type lines: list
    :param lines: items to validate

    :type content_type: str
    :param content_type: the content_type of lines

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request
    """
    request_url = f'{BACKSTORY_API_V2_URL}/lists:verifyReferenceList'
    content_type = 'CONTENT_TYPE_DEFAULT_STRING' if content_type == DEFAULT_CONTENT_TYPE else content_type
    body = {
        'lines': lines,
        'content_type': content_type
    }
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(body))
    json_data['command_name'] = 'gcb-verify-reference-list'
    json_data['success'] = json_data.get('success', False)
    json_data['errors'] = json_data.get('errors', [])
    ec = {
        CHRONICLE_OUTPUT_PATHS['VerifyReferenceList']: json_data
    }
    return ec, json_data


def gcb_test_rule_stream(client_obj, rule_text, start_time, end_time, max_results):
    """
    Return context data and raw response for gcb-test-rule-stream.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_text: str
    :param rule_text: the rule text to for the rule to be created

    :type start_time: str
    :param start_time: start time of the window

    :type end_time: str
    :param end_time: end time of the window

    :type max_results: int
    :param max_results: maximum number of results to return

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the created rule
    """
    req_json_data = {
        'rule': {
            'ruleText': rule_text,
        },
        "startTime": start_time,
        "endTime": end_time,
        "maxResults": max_results
    }
    request_url = f"{BACKSTORY_API_V2_URL}/detect/rules:streamTestRule"
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(req_json_data))

    # context data for the command
    ec = {
        CHRONICLE_OUTPUT_PATHS['StreamRules']: {'list': json_data}
    }
    return ec, json_data


def gcb_list_asset_aliases(client_obj: Client, start_time: str, end_time: str, page_size: Optional[int],
                           asset_identifier_type: Optional[str], asset_identifier: str) -> \
        tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-asset-aliases-list command.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type start_time: str
    :param start_time: Start time of the window.

    :type end_time: str
    :param end_time: End time of the window.

    :type page_size: int
    :param page_size: Maximum number of results to return.

    :type asset_identifier_type: str
    :param asset_identifier_type: Type of the asset identifier.

    :type asset_identifier: str
    :param asset_identifier: Asset Identifier value.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for asset aliases.
    """
    request_url = (f"{BACKSTORY_API_V1_URL}/alias/listassetaliases?asset.{asset_identifier_type}={asset_identifier}"
                   f"&start_time={start_time}&end_time={end_time}&page_size={page_size}")
    json_data = validate_response(client_obj, request_url, method='GET')

    # context data for the command
    ec = {
        CHRONICLE_OUTPUT_PATHS['AssetAliases']: {
            "asset": {asset_identifier_type: urllib.parse.unquote(asset_identifier),
                      "aliases": json_data.get('aliases')}}
    }
    return ec, json_data


def gcb_list_curated_rules(client_obj: Client, page_token: str, page_size: Optional[int]) -> \
        tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-list-curatedrules command.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type page_token: str
    :param page_token: Page token for pagination.

    :type page_size: int
    :param page_size: Maximum number of results to return.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for asset aliases.
    """
    request_url = f"{BACKSTORY_API_V2_URL}/detect/curatedRules?page_size={page_size}"
    if page_token:
        request_url += f"&page_token={page_token}"
    json_data = validate_response(client_obj, request_url, method='GET')

    # context data for the command
    ec = {
        CHRONICLE_OUTPUT_PATHS['CuratedRules']: json_data.get('curatedRules', [])
    }
    if json_data.get('nextPageToken'):
        token_ec = {'name': 'gcb-list-curatedrules', 'nextPageToken': json_data.get('nextPageToken', '')}
        ec.update({CHRONICLE_OUTPUT_PATHS['Token']: token_ec})
    return ec, json_data


def gcb_list_user_aliases(client_obj: Client, start_time: str, end_time: str, page_size: Optional[int],
                          user_identifier_type: Optional[str], user_identifier: str) -> \
        tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-user-aliases-list command.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type start_time: str
    :param start_time: Start time of the window.

    :type end_time: str
    :param end_time: End time of the window.

    :type page_size: int
    :param page_size: Maximum number of results to return.

    :type user_identifier_type: str
    :param user_identifier_type: Type of the user identifier.

    :type user_identifier: str
    :param user_identifier: User identifier value.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for user aliases.
    """
    request_url = (f"{BACKSTORY_API_V1_URL}/alias/listuseraliases?user.{user_identifier_type}={user_identifier}"
                   f"&start_time={start_time}&end_time={end_time}&page_size={page_size}")
    json_data = validate_response(client_obj, request_url, method='GET')

    # context data for the command
    ec = {
        CHRONICLE_OUTPUT_PATHS['UserAliases']: {
            "user": {user_identifier_type: urllib.parse.unquote(user_identifier),
                     "aliases": json_data.get('userAliases')}}
    }
    return ec, json_data


def gcb_verify_rule(client_obj: Client, rule_text: str):
    """
    Return context data and raw response for gcb_verify_rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_text: str
    :param rule_text: items to validate.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request.
    """
    req_json_data = {
        'ruleText': rule_text
    }
    request_url = f"{BACKSTORY_API_V2_URL}/detect/rules:verifyRule"
    json_data = validate_response(client_obj, request_url, method='POST', body=json.dumps(req_json_data))
    context_data = {
        **json_data,
        'success': json_data.get('success', False),
        'command_name': 'gcb-verify-rule',
    }

    ec = {CHRONICLE_OUTPUT_PATHS['VerifyRule']: context_data}

    return ec, json_data


''' REQUESTS FUNCTIONS '''


def test_function(client_obj, params: dict[str, Any]):
    """
    Perform test connectivity by validating a valid http response.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type params: Dict[str, Any]
    :param params: it contain configuration parameter

    :return: raise ValueError if any error occurred during connection
    :rtype: None
    """
    demisto.debug('Running Test having Proxy {}'.format(params.get('proxy')))
    request_url = f'{BACKSTORY_API_V1_URL}/ioc/listiocs?start_time=2019-10-15T20:37:00Z&page_size=1'

    validate_response(client_obj, request_url)
    demisto.results('ok')


def gcb_list_iocs_command(client_obj, args: dict[str, Any]):
    """
    List all of the IoCs discovered within your enterprise within the specified time range.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, Any]
    :param args: it contain arguments of gcb-list-ioc command

    :return: command output
    :rtype: (dict, dict, dict)
    """
    # retrieve arguments and validate it

    start_time, _, page_size, _ = get_default_command_args_value(args=args)

    # Make a request
    request_url = f'{BACKSTORY_API_V1_URL}/ioc/listiocs?start_time={start_time}&page_size={page_size}'
    json_data = validate_response(client_obj, request_url)

    # List of IoCs returned for further processing
    ioc_matches = json_data.get('response', {}).get('matches', [])
    if ioc_matches:
        ioc_matches_resp = parse_list_ioc_response(ioc_matches)

        # prepare human readable response
        hr = tableToMarkdown('IOC Domain Matches', ioc_matches_resp['hr_ioc_matches'],
                             ['Artifact', 'Category', 'Source', 'Confidence', 'Severity', 'IOC ingest time',
                              'First seen', 'Last seen'], removeNull=True)
        # prepare entry context response
        ec = {
            outputPaths['domain']: ioc_matches_resp['domain_std_context'],
            CHRONICLE_OUTPUT_PATHS['Iocs']: ioc_matches_resp['context']
        }
        return hr, ec, json_data
    else:
        return '### No domain matches found', {}, {}


def gcb_assets_command(client_obj, args: dict[str, str]):
    """
    List assets which relates to an IOC.

    This command will respond with a list of the assets which accessed the input artifact
    (ip, domain, md5, sha1, sha256) during the specified time.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-list-ioc command

    :return: command output
    """
    artifact_value = args.get('artifact_value', '')
    artifact_type = get_artifact_type(artifact_value)

    start_time, end_time, page_size, _ = get_default_command_args_value(args=args)

    request_url = (f'{BACKSTORY_API_V1_URL}/artifact/listassets?artifact.{artifact_type}={urllib.parse.quote(artifact_value)}'
                   f'&start_time={start_time}&end_time={end_time}&page_size={page_size}')

    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    if response and response.get('assets'):
        context_data, tabular_data, host_context = parse_assets_response(response, artifact_type,
                                                                         artifact_value)
        hr = tableToMarkdown(f'Artifact Accessed - {artifact_value}', tabular_data,
                             ['Host Name', 'Host IP', 'Host MAC', FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME])
        hr += '[View assets in Chronicle]({})'.format(response.get('uri', [''])[0])
        ec = {
            'Host': host_context,
            **context_data
        }
    else:
        hr = f'### Artifact Accessed: {artifact_value} \n\n'
        hr += MESSAGES["NO_RECORDS"]
    return hr, ec, response


def gcb_ioc_details_command(client_obj, args: dict[str, str]):
    """
    Fetch IoC Details from Backstory using 'listiocdetails' Search API.

    :type client_obj: Client
    :param client_obj: The Client object which abstracts the API calls to Backstory.

    :type args: dict
    :param args: the input artifact value, whose details are to be fetched.

    :return: command output (Human Readable, Context Data and Raw Response)
    :rtype: tuple
    """
    artifact_value = args.get('artifact_value', '')
    artifact_type = get_artifact_type(artifact_value)

    request_url = f'{BACKSTORY_API_V1_URL}/artifact/listiocdetails?artifact.{artifact_type}={urllib.parse.quote(artifact_value)}'
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
                                  ['Domain', IP_ADDRESS, 'Category', CONFIDENCE_SCORE, 'Severity',
                                   FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME], removeNull=True)
            hr += '[View IoC details in Chronicle]({})'.format(response.get('uri', [''])[0])
        else:
            hr += MESSAGES["NO_RECORDS"]
        return hr, ec, response

    else:
        hr += f'### For artifact: {artifact_value}\n'
        hr += MESSAGES["NO_RECORDS"]

        return hr, ec, response


def ip_command(client_obj, ip_address: str):
    """
    Reputation command for given IP address.

    :type client_obj: Client
    :param client_obj: object of the client class

    :type ip_address: str
    :param ip_address: contains arguments of reputation command ip

    :return: command output
    :rtype: tuple
    """
    if not is_ip_valid(ip_address, True):
        raise ValueError(f'Invalid IP - {ip_address}')

    request_url = f'{BACKSTORY_API_V1_URL}/artifact/listiocdetails?artifact.destination_ip_address={ip_address}'

    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    hr = ''
    if response and response.get('sources'):
        context_dict = get_context_for_ioc_details(response.get('sources', []), ip_address, 'ip')

        # preparing human readable
        hr += 'IP: ' + str(ip_address) + ' found with Reputation: ' + str(context_dict['reputation']) + '\n'
        if context_dict['hr_table_data']:
            hr += tableToMarkdown('Reputation Parameters', context_dict['hr_table_data'],
                                  ['Domain', IP_ADDRESS, 'Category', CONFIDENCE_SCORE, 'Severity',
                                   FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME])
            hr += '[View IoC details in Chronicle]({})'.format(response.get('uri', [''])[0])
        else:
            hr += MESSAGES["NO_RECORDS"]

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
            'Vendor': VENDOR,
            'Score': 0,
            'Reliability': demisto.params().get('integrationReliability')
        }

        hr += f'### IP: {ip_address} found with Reputation: Unknown\n'
        hr += MESSAGES["NO_RECORDS"]

        ec = {
            'DBotScore': dbot_context
        }

    return hr, ec, response


def domain_command(client_obj, domain_name: str):
    """
    Reputation command for given Domain address.

    :type client_obj: Client
    :param client_obj: object of the client class

    :type domain_name: str
    :param domain_name: contains arguments of reputation command domain

    :return: command output
    :rtype: tuple
    """
    request_url = f'{BACKSTORY_API_V1_URL}/artifact/listiocdetails?artifact.domain_name={urllib.parse.quote(domain_name)}'
    response = validate_response(client_obj, request_url)

    ec = {}  # type: Dict[str, Any]
    hr = ''
    if response and response.get('sources'):
        context_dict = get_context_for_ioc_details(response.get('sources', []), domain_name, 'domain')

        # preparing human readable
        hr += 'Domain: ' + str(domain_name) + ' found with Reputation: ' + str(context_dict['reputation']) + '\n'
        if context_dict['hr_table_data']:
            hr += tableToMarkdown('Reputation Parameters', context_dict['hr_table_data'],
                                  ['Domain', IP_ADDRESS, 'Category', CONFIDENCE_SCORE, 'Severity',
                                   FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME])
            hr += '[View IoC details in Chronicle]({})'.format(response.get('uri', [''])[0])
        else:
            hr += MESSAGES["NO_RECORDS"]

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
            'Vendor': VENDOR,
            'Score': 0,
            'Reliability': demisto.params().get('integrationReliability')
        }

        hr += f'### Domain: {domain_name} found with Reputation: Unknown\n'
        hr += MESSAGES["NO_RECORDS"]

        ec = {
            'DBotScore': dbot_context
        }

        return hr, ec, response


def fetch_incidents(client_obj, params: dict[str, Any]):
    """
    Fetch alerts or IoC domain matches and convert them into actionable incidents.

    :type client_obj: Client
    :param client_obj: object of the client class

    :type params: dict
    :param params: configuration parameter of fetch incidents
    :return:
    """
    first_fetch = params.get('first_fetch', DEFAULT_FIRST_FETCH).lower()  # 3 days as default
    max_fetch = params.get('max_fetch', 10)  # default page size
    time_window = params.get('time_window', '15')

    # getting numeric value from string representation
    start_time, end_time = arg_to_datetime(first_fetch), datetime.now()
    start_time, end_time = start_time.strftime(DATE_FORMAT), end_time.strftime(DATE_FORMAT)  # type: ignore

    # backstory_alert_type will create actionable incidents based on input selection in configuration
    backstory_alert_type = params.get('backstory_alert_type', 'ioc domain matches').lower()

    incidents = []

    if backstory_alert_type == "assets with alerts":
        incidents = fetch_incidents_asset_alerts(client_obj, params, start_time, end_time, time_window, max_fetch)
    elif backstory_alert_type == "user alerts":
        incidents = fetch_incidents_user_alerts(client_obj, params, start_time, end_time, time_window, max_fetch)
    elif backstory_alert_type == 'detection alerts':
        incidents = fetch_incidents_detection_alerts(client_obj, params, start_time, end_time, time_window, max_fetch)
    elif backstory_alert_type == 'curated rule detection alerts':
        incidents = fetch_incidents_curatedrule_detection_alerts(client_obj, params, start_time, end_time, time_window,
                                                                 max_fetch)
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


def gcb_list_alerts_command(client_obj, args: dict[str, Any]):
    """
    List alerts which relates to an asset.

    This method fetches alerts that are correlated to the asset under investigation.
    :type client_obj: Client
    :param client_obj:

    :type args: Dict
    :param args: inputs to fetch alerts from a specified date range. start_time, end_time, and page_size are
        considered for pulling the data.
    """
    start_time, end_time, page_size, _ = get_default_command_args_value(args=args, max_page_size=100000)

    alert_type = args.get('alert_type', 'Asset Alerts').lower()

    if alert_type not in ["asset alerts", "user alerts"]:
        raise ValueError('Allowed value for alert type should be either "Asset Alerts" or "User Alerts".')

    if alert_type == 'asset alerts':
        severity_filter = args.get('severity', 'ALL')

        # gathering all the alerts from Backstory
        alerts = get_gcb_alerts(client_obj, start_time, end_time, page_size, severity_filter)
        if not alerts:
            hr = '### Security Alert(s): '
            hr += MESSAGES["NO_RECORDS"]
            return hr, {}, {}

        # prepare alerts into human readable
        hr = convert_alerts_into_hr(alerts)

        # Remove Url key in context data
        for alert in alerts:
            for alert_info in alert.get('AlertInfo', []):
                if 'Uri' in alert_info:
                    del alert_info['Uri']
        ec = {
            CHRONICLE_OUTPUT_PATHS['Alert']: alerts
        }

        return hr, ec, alerts
    else:
        hr, ec, raw_alert = get_user_alert_hr_and_ec(client_obj, start_time, end_time, page_size)
        return hr, ec, raw_alert


def gcb_list_events_command(client_obj, args: dict[str, str]):
    """
    List all of the events discovered within your enterprise on a particular device within the specified time range.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-list-ioc command

    :return: command output
    :rtype: str, dict, dict
    """
    asset_identifier_type = ASSET_IDENTIFIER_NAME_DICT.get(args.get('asset_identifier_type', '').lower(),
                                                           args.get('asset_identifier_type', ''))
    asset_identifier = urllib.parse.quote(args.get('asset_identifier', ''))

    # retrieve arguments and validate it
    start_time, end_time, page_size, reference_time = get_default_command_args_value(args=args, date_range='2 hours')

    if not reference_time:
        reference_time = args.get('reference_time', start_time)

    # Make a request URL
    request_url = (f'{BACKSTORY_API_V1_URL}/asset/listevents?asset.{asset_identifier_type}={asset_identifier}'
                   f'&start_time={start_time}&end_time={end_time}&page_size={page_size}&reference_time={reference_time}')

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
            demisto.error(f'Event timestamp of the last event: {last_event_timestamp} is invalid.')
            hr += ' An error occurred while fetching the start time that could have been used to' \
                  ' fetch next set of events.'
        else:
            hr += f' To fetch the next set of events, execute the command with the start time as {last_event_timestamp}.' \


    parsed_ec = get_context_for_events(json_data.get('events', []))

    ec = {
        CHRONICLE_OUTPUT_PATHS["Events"]: parsed_ec
    }

    return hr, ec, json_data


def gcb_udm_search_command(client_obj, args: dict[str, str]):
    """
    List all the events discovered within your enterprise for the specified query within the specified time range.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: It contain arguments of gcb-udm-search command.

    :return: Command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    start_time, end_time, limit, query = get_gcb_udm_search_command_args_value(args=args, date_range='3 days')

    # Make a request URL
    request_url = (f'{BACKSTORY_API_V1_URL}/events:udmSearch?time_range.start_time={start_time}&time_range.end_time={end_time}'
                   f'&limit={limit}&query={query}')

    # get list of events from Chronicle Backstory
    json_data = validate_response(client_obj, request_url)

    events = json_data.get('events', [])
    if not events:
        hr = 'No events were found for the specified UDM search query.'
        return hr, {}, {}

    events = [event.get('udm', {}) for event in events]

    # prepare alerts into human-readable
    hr = get_udm_search_events_hr(events)

    if json_data.get('moreDataAvailable', False):
        last_event_timestamp = events[-1].get('metadata', {}).get('eventTimestamp', '')
        hr += '\n\nMaximum number of events specified in limit has been returned. There might' \
              ' still be more events in your Chronicle account.'
        if not dateparser.parse(last_event_timestamp, settings={'STRICT_PARSING': True}):
            demisto.error(f'Event timestamp of the last event: {last_event_timestamp} is invalid.')
            hr += ' An error occurred while fetching the end time that could have been used to' \
                  ' fetch next set of events.'
        else:
            hr += f' To fetch the next set of events, execute the command with the end time as {last_event_timestamp}.' \


    parsed_ec = get_context_for_events(events)

    ec = {
        CHRONICLE_OUTPUT_PATHS["UDMEvents"]: parsed_ec
    }

    return hr, ec, json_data


def gcb_list_detections_command(client_obj, args: dict[str, str]):
    """
    Return the Detections for a specified Rule Version.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
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
              f' detections, execute the command with the page token as {next_page_token}.'

    return hr, ec, json_data


def gcb_list_curatedrule_detections_command(client_obj, args: dict[str, str]):
    """
    Return the Detections for a specified Curated Rule ID.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type args: Dict[str, str]
    :param args: It contain arguments of gcb-list-curatedrule-detections command.

    :return: Command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    valid_args = validate_and_parse_list_curatedrule_detections_args(args)

    ec, json_data = get_curatedrule_detections(client_obj, args.get('id', ''), valid_args.get('page_size', ''),
                                               valid_args.get('detection_start_time', ''),
                                               valid_args.get('detection_end_time', ''), args.get('page_token', ''),
                                               args.get('alert_state', ''), args.get('list_basis', ''))

    detections = json_data.get('curatedRuleDetections', [])
    if not detections:
        hr = 'No Curated Detections Found'
        return hr, {}, {}

    # prepare alerts into human-readable
    hr = get_list_curatedrule_detections_hr(detections, args.get('id', ''))
    hr += '\nView all Curated Detections for this rule in Chronicle by clicking on {} and to view individual ' \
          'detection in Chronicle click on its respective Detection ID.'.format(
              detections[0].get('detection')[0].get('ruleName'))

    next_page_token = json_data.get('nextPageToken')
    if next_page_token:
        hr += '\nMaximum number of detections specified in page_size has been returned. To fetch the next set of' \
              f' detections, execute the command with the page token as {next_page_token}.'

    return hr, ec, json_data


def gcb_list_rules_command(client_obj, args: dict[str, str]):
    """
    Return the latest version of all rules.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
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
              f' rules, execute the command with the page token as {next_page_token}.'

    return hr, ec, json_data


def gcb_create_rule_command(client_obj, args: dict[str, str]):
    """
    Create a new rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains the arguments for the gcb-create-rule command.
    """
    rule_text = args.get('rule_text', '')
    validate_rule_text(rule_text)

    ec, json_data = create_rule(client_obj, rule_text)

    hr = prepare_hr_for_create_rule(json_data)

    return hr, ec, json_data


def gcb_get_rule_command(client_obj, args):
    """
    Retrieve the rule details of specified Rule ID or Version ID.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments of gcb-get-rule command

    :return: command output
    :rtype: str, dict, dict
    """
    validate_argument(args.get('id'), 'id')
    ec, json_data = gcb_get_rule(client_obj, args.get('id'))
    hr = prepare_hr_for_gcb_get_rule_command(json_data)
    return hr, ec, json_data


def gcb_delete_rule_command(client_obj, args: dict[str, str]):
    """
    Delete an already existing rule.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains the arguments for the gcb-delete-rule command.
    """
    rule_id = args.get('rule_id', '')
    validate_argument(value=rule_id, name='rule_id')

    ec, json_data = delete_rule(client_obj, rule_id)

    hr = prepare_hr_for_delete_rule(json_data)

    return hr, ec, json_data


def gcb_create_rule_version_command(client_obj, args):
    """
    Create a new version of an existing rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-create-rule-version command

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get('rule_id'), 'rule_id')
    rule_text = validate_argument(args.get('rule_text'), 'rule_text')
    validate_rule_text(rule_text)
    ec, json_data = gcb_create_rule_version(client_obj, rule_id, rule_text)
    hr = prepare_hr_for_gcb_create_rule_version_command(json_data)
    return hr, ec, json_data


def gcb_change_rule_alerting_status_command(client_obj, args):
    """
    Change the alerting status of a rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments of gcb-change-rule-alerting-status command

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get('rule_id'), 'rule_id')
    alerting_status = validate_argument(args.get('alerting_status'), 'alerting_status')
    validate_single_select(alerting_status, 'alerting_status', ['enable', 'disable'])
    ec, json_data = gcb_change_rule_alerting_status(client_obj, rule_id, alerting_status)
    hr = prepare_hr_for_gcb_change_rule_alerting_status(json_data, alerting_status)
    return hr, ec, json_data


def gcb_change_live_rule_status_command(client_obj, args):
    """
    Change the live status of an existing rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-change-live-rule-status command

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get('rule_id'), 'rule_id')
    live_rule_status = validate_argument(args.get('live_rule_status'), 'live_rule_status')
    validate_single_select(live_rule_status, 'live_rule_status', ['enable', 'disable'])
    ec, json_data = gcb_change_live_rule_status(client_obj, rule_id, live_rule_status)
    hr = prepare_hr_for_gcb_change_live_rule_status_command(json_data, live_rule_status)
    return hr, ec, json_data


def gcb_start_retrohunt_command(client_obj, args):
    """
    Initiate a retrohunt for the specified rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-start-retrohunt command

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get('rule_id'), 'rule_id')
    start_time = arg_to_datetime(args.get('start_time', '1 week'), 'start_time').strftime(DATE_FORMAT)  # type: ignore
    end_time = arg_to_datetime(args.get('end_time', '10 min'), 'end_time').strftime(DATE_FORMAT)  # type: ignore

    ec, json_data = gcb_start_retrohunt(client_obj, rule_id, start_time, end_time)
    hr = prepare_hr_for_gcb_start_retrohunt_command(json_data)

    return hr, ec, json_data


def gcb_list_retrohunts_command(client_obj, args):
    """
    List retrohunts for a rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-create-rule-version command

    :return: command output
    :rtype: str, dict, dict
    """
    valid_args = validate_list_retrohunts_args(args)
    ec, json_data = gcb_list_retrohunts(client_obj, valid_args.get('rule_id'),
                                        valid_args.get('retrohunts_for_all_versions'), valid_args.get('state'),
                                        valid_args.get('page_size'), valid_args.get('page_token'))
    if not json_data:
        return "## RetroHunt Details\nNo Records Found.", {}, {}
    hr = prepare_hr_for_gcb_list_retrohunts_commands(json_data)
    return hr, ec, json_data


def gcb_get_retrohunt_command(client_obj, args):
    """
    Get retrohunt for a specific version of a rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-get-retrohunt command

    :rtype: str, dict, dict
    :return command output
    """
    rule_or_version_id = validate_argument(args.get('id'), 'id')
    retrohunt_id = validate_argument(args.get('retrohunt_id'), 'retrohunt_id')

    ec, json_data = gcb_get_retrohunt(client_obj, rule_or_version_id=rule_or_version_id, retrohunt_id=retrohunt_id)
    hr = prepare_hr_for_get_retrohunt(retrohunt_details=json_data)

    return hr, ec, json_data


def gcb_cancel_retrohunt_command(client_obj, args):
    """
    Cancel a retrohunt for a specified rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-cancel-retrohunt command

    :rtype: str, dict, dict
    :return command output
    """
    rule_or_version_id = validate_argument(args.get('id'), 'id')
    retrohunt_id = validate_argument(args.get('retrohunt_id'), 'retrohunt_id')
    ec, json_data = gcb_cancel_retrohunt(client_obj, rule_or_version_id, retrohunt_id)
    hr = prepare_hr_for_gcb_cancel_retrohunt(json_data)
    return hr, ec, json_data


def gcb_create_reference_list_command(client_obj, args):
    """
    Create a new reference list.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-create-reference-list command

    :rtype: str, dict, dict
    :return command output
    """
    name = validate_argument(args.get('name'), 'name')
    description = validate_argument(args.get('description'), 'description')
    lines = validate_argument(args.get('lines'), 'lines')
    lines = argToList(lines, args.get('delimiter', ','))
    valid_lines = [line for line in lines if line]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, 'lines')  # Validation for empty lines list
    content_type = validate_single_select(
        args.get('content_type', DEFAULT_CONTENT_TYPE).upper(), 'content_type', VALID_CONTENT_TYPE)
    ec, json_data = gcb_create_reference_list(client_obj, name=name, description=description,
                                              lines=lines, content_type=content_type)
    hr = prepare_hr_for_gcb_create_get_update_reference_list(json_data)
    return hr, ec, json_data


def gcb_list_reference_list_command(client_obj, args):
    """
    List all the reference lists.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-list-reference-list command

    :return: command output
    :rtype: str, dict, dict
    """
    page_size = args.get('page_size', 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))
    page_token = args.get('page_token', '')
    view = validate_single_select(args.get('view', 'BASIC'), 'view', ['BASIC', 'FULL'])

    ec, json_data = gcb_list_reference_list(client_obj, page_size, page_token, view)
    hr = prepare_hr_for_gcb_list_reference_list(json_data)

    return hr, ec, json_data


def gcb_get_reference_list_command(client_obj, args):
    """
    Return the specified list.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-list-reference-list command

    :return: command output
    :rtype: str, dict, dict
    """
    name = validate_argument(args.get('name'), 'name')
    view = validate_single_select(args.get('view', 'FULL'), 'view', ['FULL', 'BASIC'])
    ec, json_data = gcb_get_reference_list(client_obj, name=name, view=view)
    hr = prepare_hr_for_gcb_create_get_update_reference_list(json_data)
    return hr, ec, json_data


def gcb_update_reference_list_command(client_obj, args):
    """
    Update an existing reference list.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-update-reference-list command

    :return: command output
    :rtype: str, dict, dict
    """
    name = validate_argument(args.get('name'), 'name')
    lines = validate_argument(args.get('lines'), 'lines')
    lines = argToList(lines, args.get('delimiter', ','))
    valid_lines = [line for line in lines if line]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, 'lines')  # Validation for empty lines list
    description = args.get('description')
    content_type = args.get('content_type')
    if not content_type:
        # Get the content type from the reference list
        request_url = f'{BACKSTORY_API_V2_URL}/lists/{name}'
        json_data = validate_response(client_obj, request_url, method='GET')
        content_type = json_data.get('contentType', DEFAULT_CONTENT_TYPE)

    content_type = validate_single_select(content_type.upper(), 'content_type', VALID_CONTENT_TYPE)
    ec, json_data = gcb_update_reference_list(client_obj, name=name, lines=lines,
                                              description=description, content_type=content_type)
    hr = prepare_hr_for_gcb_create_get_update_reference_list(json_data, 'Updated Reference List Details')
    return hr, ec, json_data


def gcb_verify_reference_list_command(client_obj, args):
    """
    Validate lines contents.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-update-reference-list command

    :return: command output
    :rtype: str, dict, dict
    """
    lines = validate_argument(args.get('lines'), 'lines')
    lines = argToList(lines, args.get('delimiter', ','))
    valid_lines = [line for line in lines if line]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, 'lines')  # Validation for empty lines list
    content_type = validate_single_select(
        args.get('content_type', DEFAULT_CONTENT_TYPE).upper(), 'content_type', VALID_CONTENT_TYPE)

    ec, json_data = gcb_verify_reference_list(client_obj, lines=lines, content_type=content_type)
    hr = prepare_hr_for_verify_reference_list(json_data, content_type)
    return hr, ec, json_data


def gcb_verify_value_in_reference_list_command(client_obj, args):
    """
    Check if the value is present in the reference list.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: It contains arguments for gcb-verify-value-in-reference-list command.

    :return: command output
    :rtype: str, dict, dict
    """
    delimiter = args.get('delimiter', ',')
    reference_lists_names = argToList(args.get('reference_list_names', []))
    search_values = argToList(args.get('values', []), separator=delimiter)
    case_insensitive = argToBoolean(args.get('case_insensitive_search', 'false'))
    add_not_found_reference_lists = argToBoolean(args.get('add_not_found_reference_lists', 'false'))

    reference_lists = validate_argument(get_unique_value_from_list(
        [reference_list.strip() for reference_list in reference_lists_names]), 'reference_list_names')
    values = validate_argument(get_unique_value_from_list([value.strip() for value in search_values]), 'values')

    found_reference_lists = {}
    not_found_reference_lists = []

    for reference_list in reference_lists:
        try:
            _, json_data = gcb_get_reference_list(client_obj, name=reference_list, view='FULL')
            found_reference_lists[reference_list] = json_data.get('lines', [])
        except Exception:
            not_found_reference_lists.append(reference_list)

    if not_found_reference_lists:
        return_warning('The following Reference lists were not found: {}'.format(', '.join(not_found_reference_lists)),
                       exit=len(not_found_reference_lists) == len(reference_lists))

    if case_insensitive:
        for reference_list, lines in found_reference_lists.items():
            found_reference_lists[reference_list] = [line.lower() for line in lines]

    hr_dict, json_data, ec_data = [], [], []
    for value in values:
        overall_status = 'Not Found'
        found_lists, not_found_lists = [], []
        for reference_list, lines in found_reference_lists.items():
            if value in lines:
                found_lists.append(reference_list)
            elif case_insensitive and value.lower() in lines:
                found_lists.append(reference_list)
            else:
                not_found_lists.append(reference_list)

        if found_lists:
            overall_status = 'Found'

        result = {
            'value': value,
            'found_in_lists': found_lists,
            'not_found_in_lists': not_found_lists,
            'overall_status': overall_status,
            'case_insensitive': case_insensitive
        }
        json_data.append(result)
        data = deepcopy(result)

        hr_data = {
            'value': string_escape_markdown(value),
            'found_in_lists': ', '.join(found_lists),
            'not_found_in_lists': ', '.join(not_found_lists),
            'overall_status': overall_status
        }

        if not add_not_found_reference_lists:
            hr_data['not_found_in_lists'] = []
            data['not_found_in_lists'] = []

        ec_data.append(data)
        hr_dict.append(hr_data)

    title = 'Successfully searched provided values in the reference lists in Google Chronicle.'
    hr = tableToMarkdown(title, hr_dict, ['value', 'found_in_lists', 'not_found_in_lists', 'overall_status'],
                         headerTransform=header_transform_to_title_case, removeNull=True)
    ec = {
        CHRONICLE_OUTPUT_PATHS['VerifyValueInReferenceList']: ec_data
    }

    return hr, ec, json_data


def header_transform_to_title_case(string: str) -> str:
    '''
    Header transform function to convert given string to title case with the spaces between words.

    :type string: ``str``
    :param string: The string to convert to title case.

    :return: The string in title case.
    '''
    new_string = string.split('_')
    new_string = [i.capitalize() for i in new_string]
    return ' '.join(new_string)


def prepare_hr_for_gcb_test_rule_stream_command(detections):
    """
    Prepare Human Readable output from the response received.

    :type detections: Dict
    :param detections: raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    hr_dict = []
    for detection in detections:
        detection = detection.get('detection', {})
        events = get_event_list_for_detections_hr(detection.get('collectionElements', []))
        hr_dict.append({
            'Detection ID': detection.get('id', ''),
            'Detection Type': detection.get('type', ''),
            'Detection Time': detection.get('detectionTime', ''),
            'Events': get_events_hr_for_detection(events)
        })
    hr = tableToMarkdown('Detection(s)', hr_dict, ['Detection ID', 'Detection Type', 'Detection Time', 'Events'],
                         removeNull=True)
    return hr


def prepare_hr_for_gcb_list_asset_aliases_command(aliases_response: dict[str, Any], asset_identifier: str) -> str:
    """
    Prepare Human Readable output from the response received.

    :type aliases_response: Dict
    :param aliases_response: Raw response received from api in json format.

    :type asset_identifier: str
    :param asset_identifier: Value of the asset identifier.

    :return: Human Readable output to display.
    :rtype: str
    """
    aliases = aliases_response.get('aliases', [])
    hr_dict = []
    if len(aliases) == 1:
        return MESSAGES['EMPTY_ASSET_ALIASES'].format(asset_identifier)
    for alias in aliases:
        metadata = alias.get('metadata', {})
        asset = alias.get('entity', {}).get('asset', {})
        hr_dict.append({
            'Asset ID': asset.get('assetId'),
            'Host Name': asset.get('hostname'),
            'IP Address': asset.get('ip'),
            'MAC Address': asset.get('mac')[0] if asset.get('mac') else None,
            'Start Time': metadata.get('interval', {}).get('startTime'),
            'End Time': metadata.get('interval', {}).get('endTime')
        })
    hr = tableToMarkdown('Asset Aliases:', hr_dict,
                         ['Asset ID', 'Host Name', 'IP Address', 'MAC Address', 'Start Time', 'End Time'],
                         removeNull=True)
    return hr


def prepare_hr_for_gcb_list_curated_rules_command(aliases_response: dict[str, Any]) -> str:
    """
    Prepare Human Readable output from the response received.

    :type aliases_response: Dict
    :param aliases_response: Raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    curated_rules = aliases_response.get('curatedRules', [])
    hr_dict = []
    for rule in curated_rules:
        hr_dict.append({
            'Rule ID': rule.get('ruleId'),
            'Rule Name': rule.get('ruleName'),
            'Severity': rule.get('severity'),
            'Rule Type': rule.get('ruleType'),
            'Rule Set': rule.get('ruleSet'),
            'Description': rule.get('description'),
        })
    hr = tableToMarkdown('Curated Rules:', hr_dict,
                         ['Rule ID', 'Rule Name', 'Severity', 'Rule Type', 'Rule Set', 'Description'],
                         removeNull=True)
    next_page_token = aliases_response.get('nextPageToken')
    if next_page_token:
        hr += '\nMaximum number of curated rules specified in page_size has been returned. To fetch the next set of' \
              f' curated rules, execute the command with the page token as {next_page_token}.'

    return hr


def prepare_hr_for_gcb_list_user_aliases_command(aliases_response: dict[str, Any]) -> str:
    """
    Prepare Human Readable output from the response received.

    :type aliases_response: Dict
    :param aliases_response: Raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    aliases = aliases_response.get('userAliases', [])
    hr_dict = []
    for alias in aliases:
        metadata = alias.get('metadata', {})
        user = alias.get('entity', {}).get('user', {})
        asset = alias.get('entity', {}).get('asset', {})
        hr_dict.append({
            'User ID': user.get('userid'),
            'Product Object ID': user.get('productObjectId'),
            'Product Name': metadata.get('productName'),
            'Vendor Name': metadata.get('vendorName'),
            'Asset ID': asset.get('assetId'),
            'IP': ', '.join(asset.get('ip')) if asset.get('ip') else None,
            'Hostname': asset.get('hostname'),
            'Title': user.get('title'),
            'Company Name': user.get('companyName'),
            'Start Time': metadata.get('interval', {}).get('startTime'),
            'End Time': metadata.get('interval', {}).get('endTime')
        })
    hr = tableToMarkdown('User Aliases:', hr_dict,
                         ['User ID', 'Product Object ID', 'Product Name', 'Vendor Name', 'Asset ID', 'IP', 'Hostname',
                          'Title', 'Company Name', 'Start Time', 'End Time'], removeNull=True)
    return hr


def gcb_test_rule_stream_command(client_obj, args):
    """
    Stream results for given rule text.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-update-reference-list command

    :rtype: str, dict, dict
    :return: command output
    """
    rule_text = args.get('rule_text', '')
    start_time = arg_to_datetime(args.get('start_time'), 'start_time').strftime(DATE_FORMAT)  # type: ignore
    end_time = arg_to_datetime(args.get('end_time'), 'end_time').strftime(DATE_FORMAT)  # type: ignore
    max_results = arg_to_number(args.get('max_results', 1000))

    validate_rule_text(rule_text)
    if max_results > 10000 or max_results <= 0:  # type: ignore
        raise ValueError(MESSAGES["INVALID_MAX_RESULTS"])

    ec, json_data = gcb_test_rule_stream(client_obj, rule_text=rule_text, start_time=start_time, end_time=end_time,
                                         max_results=max_results)
    hr = prepare_hr_for_gcb_test_rule_stream_command(json_data)  # select fields to be shown in HR
    return hr, ec, json_data


def gcb_list_asset_aliases_command(
        client_obj: Client, args: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """
    List asset aliases for the specified asset identifier.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type args: Dict[str, Any]
    :param args: It contains arguments for gcb-asset-aliases command.

    :rtype: str, dict, dict
    :return: Command output.
    """
    asset_identifier_type = ASSET_IDENTIFIER_NAME_DICT.get(args.get('asset_identifier_type', '').lower())
    asset_identifier = urllib.parse.quote(args.get('asset_identifier', ''))
    start_time = arg_to_datetime(args.get('start_time', '3 days'), 'start_time').strftime(DATE_FORMAT)  # type: ignore
    end_time = arg_to_datetime(args.get('end_time', 'now'), 'end_time').strftime(DATE_FORMAT)  # type: ignore
    page_size = args.get('page_size', '10000')

    validate_list_asset_aliases_args(asset_identifier_type, asset_identifier, page_size)

    page_size = arg_to_number(page_size, arg_name='page_size')

    ec, json_data = gcb_list_asset_aliases(client_obj, start_time=start_time, end_time=end_time, page_size=page_size,
                                           asset_identifier_type=asset_identifier_type,
                                           asset_identifier=asset_identifier)
    hr = prepare_hr_for_gcb_list_asset_aliases_command(json_data, args.get('asset_identifier', ''))
    return hr, ec, json_data


def gcb_list_curated_rules_command(
        client_obj: Client, args: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """
    List curated rules from Google Chronicle Backstory.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type args: Dict[str, Any]
    :param args: It contains arguments for gcb-list-curatedrules command.

    :rtype: str, dict, dict
    :return: Command output.
    """
    page_token = urllib.parse.quote(args.get('page_token', ''))
    page_size = args.get('page_size', '100')

    validate_list_curated_rules_args(page_size)

    page_size = arg_to_number(page_size, arg_name='page_size')

    ec, json_data = gcb_list_curated_rules(client_obj, page_token, page_size)
    hr = prepare_hr_for_gcb_list_curated_rules_command(json_data)
    return hr, ec, json_data


def gcb_list_user_aliases_command(
        client_obj: Client, args: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """
    List user aliases for the specified user identifier.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type args: Dict[str, Any]
    :param args: It contains arguments for gcb-user-aliases command.

    :rtype: str, dict, dict
    :return: Command output.
    """
    user_identifier_type = USER_IDENTIFIER_NAME_DICT.get(args.get('user_identifier_type', '').lower())
    user_identifier = urllib.parse.quote(args.get('user_identifier', ''))
    start_time = arg_to_datetime(args.get('start_time', '3 days'), 'start_time').strftime(DATE_FORMAT)  # type: ignore
    end_time = arg_to_datetime(args.get('end_time', 'now'), 'end_time').strftime(DATE_FORMAT)  # type: ignore
    page_size = args.get('page_size', '10000')

    validate_list_user_aliases_args(user_identifier_type, user_identifier, page_size)

    page_size = arg_to_number(page_size, arg_name='page_size')

    ec, json_data = gcb_list_user_aliases(client_obj, start_time=start_time, end_time=end_time, page_size=page_size,
                                          user_identifier_type=user_identifier_type,
                                          user_identifier=user_identifier)
    hr = prepare_hr_for_gcb_list_user_aliases_command(json_data)
    return hr, ec, json_data


def gcb_verify_rule_command(client_obj, args):
    """
    Verify the rule has valid YARA-L 2.0 format.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type args: Dict[str, Any]
    :param args: It contains arguments for gcb-verify-rule command.

    :rtype: str, dict, dict
    :return: Command output.
    """
    rule_text = args.get('rule_text', '')
    validate_rule_text(rule_text)

    ec, json_data = gcb_verify_rule(client_obj, rule_text)

    success = json_data.get('success')
    context = json_data.get('context')

    if success:
        hr = f'### {context.capitalize()}'
    else:
        hr = f'### Error: {context}'

    return hr, ec, json_data


def gcb_get_event_command(client_obj, args: dict[str, str]):
    """
    Get specific event With the given ID.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-get-event command

    :return: command output
    :rtype: str, dict, dict
    """

    event_id = validate_argument(args.get('event_id'), 'event_id')
    event_id = urllib.parse.quote(event_id)

    request_url = f'{BACKSTORY_API_V1_URL}/event:get?name={event_id}'

    json_data = validate_response(client_obj, request_url)

    event_data = deepcopy(json_data.get('udm', {}))

    hr = prepare_hr_for_gcb_get_event(deepcopy(event_data))

    parsed_ec = get_context_for_events([event_data])
    ec = {
        CHRONICLE_OUTPUT_PATHS["Events"]: parsed_ec
    }

    return hr, ec, json_data


def prepare_hr_for_gcb_get_event(event: dict[str, Any]):
    """
    Prepare Human Readable output from the response received.

    :type event: Dict
    :param event: raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    event = convert_numbers_to_strings_for_object(event)

    metadata = event.get('metadata', {})
    event_id = metadata.get('id', '')
    human_readable = (
        tableToMarkdown(f'General Information for the given event with ID: {event_id}', metadata, removeNull=True,
                        headerTransform=convert_string_table_case_to_title_case, is_auto_json_transform=True,)
        if metadata else '')

    principal_info = event.get('principal', {})
    human_readable += ('\n' + tableToMarkdown('Principal Information', principal_info, is_auto_json_transform=True,
                                              headerTransform=convert_string_table_case_to_title_case, removeNull=True)
                       if principal_info else '')

    target_info = event.get('target', {})
    human_readable += ('\n' + tableToMarkdown('Target Information', target_info, is_auto_json_transform=True,
                                              headerTransform=convert_string_table_case_to_title_case, removeNull=True)
                       if target_info else '')

    security_result_info = event.get('securityResult', [])
    human_readable += ('\n' + tableToMarkdown('Security Result Information', security_result_info, is_auto_json_transform=True,
                                              headerTransform=convert_string_table_case_to_title_case, removeNull=True)
                       if security_result_info else '')

    network_info = event.get('network', {})
    human_readable += ('\n' + tableToMarkdown('Network Information', network_info, is_auto_json_transform=True,
                                              headerTransform=convert_string_table_case_to_title_case, removeNull=True)
                       if network_info else '')
    return human_readable


def convert_numbers_to_strings_for_object(d: Any) -> Any:
    """
    Recursively convert all integer and float values in a object to strings,

    :param d: Input object.
    :type d: Any
    :return: An object with all integer and float values converted to strings.
    :rtype: Any
    """

    def convert(x: Any) -> Any:
        """
        Recursively convert all integer and float values in a nested data structure to strings.

        :param x: A nested data structure containing the values to be converted.
        :return: A nested data structure with all integer and float values converted to strings.
        """
        if isinstance(x, (int, float)):
            return str(x)
        if isinstance(x, list):
            return [convert(v) for v in x]
        if isinstance(x, dict):
            return {k: convert(v) for k, v in x.items()}
        return x

    if not isinstance(d, (dict, list)):
        return convert(d)
    if isinstance(d, list):
        return [convert(v) for v in d]
    return {k: convert(v) for k, v in d.items()}


def convert_string_table_case_to_title_case(input_str: str) -> str:
    """
    Convert string in table case to title case.

    :type input_str: str
    :param input_str: string in table case.

    :return: string in title case
    """
    transformed = re.sub(r'(?<=[a-z])([A-Z])', r' \1', input_str)

    return transformed.title()


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    # supported command list
    chronicle_commands = {
        'gcb-list-iocs': gcb_list_iocs_command,
        'gcb-assets': gcb_assets_command,
        'gcb-ioc-details': gcb_ioc_details_command,
        'gcb-list-alerts': gcb_list_alerts_command,
        'gcb-list-events': gcb_list_events_command,
        'gcb-list-detections': gcb_list_detections_command,
        'gcb-list-rules': gcb_list_rules_command,
        'gcb-create-rule': gcb_create_rule_command,
        'gcb-get-rule': gcb_get_rule_command,
        'gcb-delete-rule': gcb_delete_rule_command,
        'gcb-create-rule-version': gcb_create_rule_version_command,
        'gcb-change-rule-alerting-status': gcb_change_rule_alerting_status_command,
        'gcb-change-live-rule-status': gcb_change_live_rule_status_command,
        'gcb-start-retrohunt': gcb_start_retrohunt_command,
        'gcb-get-retrohunt': gcb_get_retrohunt_command,
        'gcb-list-retrohunts': gcb_list_retrohunts_command,
        'gcb-cancel-retrohunt': gcb_cancel_retrohunt_command,
        'gcb-create-reference-list': gcb_create_reference_list_command,
        'gcb-list-reference-list': gcb_list_reference_list_command,
        'gcb-get-reference-list': gcb_get_reference_list_command,
        'gcb-update-reference-list': gcb_update_reference_list_command,
        'gcb-test-rule-stream': gcb_test_rule_stream_command,
        'gcb-list-assetaliases': gcb_list_asset_aliases_command,
        'gcb-list-curatedrules': gcb_list_curated_rules_command,
        'gcb-list-useraliases': gcb_list_user_aliases_command,
        'gcb-list-curatedrule-detections': gcb_list_curatedrule_detections_command,
        'gcb-udm-search': gcb_udm_search_command,
        'gcb-verify-reference-list': gcb_verify_reference_list_command,
        'gcb-verify-value-in-reference-list': gcb_verify_value_in_reference_list_command,
        'gcb-verify-rule': gcb_verify_rule_command,
        'gcb-get-event': gcb_get_event_command,
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
            args = trim_args(demisto.args())
            return_outputs(*chronicle_commands[command](client_obj, args))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError: {str(e)}')


# initial flow of execution
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
