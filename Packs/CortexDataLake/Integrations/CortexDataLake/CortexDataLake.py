import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """
import os
import re
import json
from pan_cortex_data_lake import Credentials, exceptions, QueryService
import time
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Any
from collections.abc import Callable
from tempfile import gettempdir
from dateutil import parser
from datetime import timedelta

# disable insecure warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' GLOBAL CONSTS '''
ACCESS_TOKEN_CONST = 'access_token'  # guardrails-disable-line
EXPIRES_IN = 'expires_in'
INSTANCE_ID_CONST = 'instance_id'
API_URL_CONST = 'api_url'
FIRST_FAILURE_TIME_CONST = 'first_failure_time'
LAST_FAILURE_TIME_CONST = 'last_failure_time'
DEFAULT_API_URL = 'https://api.us.cdl.paloaltonetworks.com'
MINUTES_60 = 60 * 60
SECONDS_30 = 30
FETCH_TABLE_HR_NAME = {
    "firewall.threat": "Cortex Firewall Threat",
    "firewall.file_data": "Cortex Firewall File Data",
    "firewall.auth": "Cortex Firewall Authentication",
    "firewall.decryption": "Cortex Firewall Decryption",
    "firewall.extpcap": "Cortex Firewall Extpcap",
    "firewall.globalprotect": "Cortex Firewall GlobalProtect",
    "firewall.hipmatch": "Cortex Firewall HIP Match",
    "firewall.iptag": "Cortex Firewall IPtag",
    "firewall.traffic": "Cortex Firewall Traffic",
    "firewall.url": "Cortex Firewall URL",
    "firewall.userid": "Cortex Firewall UserID",
    "log.system": "Cortex Common System",
    "log.config": "Cortex Common Config"
}
BAD_REQUEST_REGEX = r'^Error in API call \[400\].*'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, token_retrieval_url, registration_id, use_ssl, proxy, refresh_token, enc_key, is_fr):
        headers = get_x_content_info_headers()
        headers['Authorization'] = registration_id
        headers['Accept'] = 'application/json'
        super().__init__(base_url=token_retrieval_url, headers=headers, verify=use_ssl, proxy=proxy)
        self.refresh_token = refresh_token
        self.enc_key = enc_key
        self.use_ssl = use_ssl
        self.is_fr = is_fr
        self.registration_id = registration_id
        # Trust environment settings for proxy configuration
        self.trust_env = proxy
        self._set_access_token()

    def _set_access_token(self):
        """
        Checks if access token exists in the integration context and set it to the object properties, if not, a new token
        is generated and saved in the integration context along with the query api_url and the instance_id
        Returns:
            None
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)
        valid_until = integration_context.get(EXPIRES_IN)
        if access_token and valid_until and int(time.time()) < valid_until:
            self.access_token = access_token
            self.api_url = integration_context.get(API_URL_CONST, DEFAULT_API_URL)
            self.instance_id = integration_context.get(INSTANCE_ID_CONST)
            return
        demisto.debug(f'access token time: {valid_until} expired/none. Will call oproxy')
        access_token, api_url, instance_id, refresh_token, expires_in = self._oproxy_authorize()
        updated_integration_context = {
            ACCESS_TOKEN_CONST: access_token,
            EXPIRES_IN: int(time.time()) + expires_in - SECONDS_30,
            API_URL_CONST: api_url,
            INSTANCE_ID_CONST: instance_id
        }
        if refresh_token:
            updated_integration_context.update({'refresh_token': refresh_token})
        demisto.setIntegrationContext(updated_integration_context)
        self.access_token = access_token
        self.api_url = api_url
        self.instance_id = instance_id

    def _oproxy_authorize(self) -> tuple[Any, Any, Any, Any, int]:
        oproxy_response = self._get_access_token_with_backoff_strategy()
        access_token = oproxy_response.get(ACCESS_TOKEN_CONST)
        api_url = oproxy_response.get('url')
        refresh_token = oproxy_response.get('refresh_token')
        instance_id = oproxy_response.get(INSTANCE_ID_CONST)
        # In case the response has EXPIRES_IN key with empty string as value, we need to make sure we don't try to cast
        # an empty string to an int.
        expires_in = int(oproxy_response.get(EXPIRES_IN, MINUTES_60) or 0)
        if not access_token or not api_url or not instance_id:
            raise DemistoException(f'Missing attribute in response: access_token, instance_id or api are missing.\n'
                                   f'Oproxy response: {oproxy_response}')
        return access_token, api_url, instance_id, refresh_token, expires_in

    def _get_access_token_with_backoff_strategy(self) -> dict:
        """ Implements a backoff strategy for retrieving an access token.
        Raises an exception if the call is within one of the time windows, otherwise fetches the access token

        Returns: The oproxy response or raising a DemistoException

        """
        self._backoff_strategy(demisto.getIntegrationContext())
        return self._get_access_token()

    @staticmethod
    def _backoff_strategy(integration_context: dict):
        """ Implements a backoff strategy for retrieving an access token. Logic as follows:
        - First 60 minutes check for access token once every 1 minute max.
        - Next 47 hours check for access token once every 10 minute max.
        - After 48 hours check for access token once every 60 minutes max.

        Args:
            integration_context: The integration context

        """
        err_msg = 'We have found out that your recent attempts to authenticate against the CDL server have failed. ' \
                  'Therefore we have limited the number of calls that the CDL integration performs. ' \
                  'If you wish to try authenticating again, please run the `cdl-reset-authentication-timeout` ' \
                  'command and retry. If you choose not to reset the authentication timeout, the next attempt can be ' \
                  'done in {} {}.'
        first_failure_time = integration_context.get(FIRST_FAILURE_TIME_CONST)
        last_failure_time = integration_context.get(LAST_FAILURE_TIME_CONST)
        now_datetime = datetime.utcnow()
        demisto.debug(f'CDL - First failure time: {first_failure_time}')
        demisto.debug(f'CDL - Last failure time: {last_failure_time}')
        demisto.debug(f'CDL - Current time: {last_failure_time}')

        if first_failure_time and last_failure_time:
            first_failure_datetime = datetime.fromisoformat(first_failure_time)
            last_failure_datetime = datetime.fromisoformat(last_failure_time)
            time_from_first_failure = now_datetime - first_failure_datetime
            time_from_last_failure = now_datetime - last_failure_datetime

            if time_from_first_failure < timedelta(hours=1):
                window = timedelta(minutes=1)
                if time_from_last_failure < window:
                    raise DemistoException(err_msg.format(window - time_from_last_failure, 'seconds'))
            elif time_from_first_failure < timedelta(hours=48):
                window = timedelta(minutes=10)
                if time_from_last_failure < window:
                    raise DemistoException(err_msg.format(window - time_from_last_failure, 'minutes'))
            else:
                window = timedelta(minutes=60)
                if time_from_last_failure < window:
                    raise DemistoException(err_msg.format(window - time_from_last_failure, 'minutes'))

    def _get_access_token(self) -> dict:
        """ Performs an http request to oproxy-cdl access token endpoint
        In case of failure, handles the error, otherwise reset the failure counters and return the response

        Returns: The oproxy response or raising a DemistoException

        """
        demisto.debug('CDL - Fetching access token')
        try:
            token = get_encrypted(self.refresh_token, self.enc_key)
            if self.is_fr:
                data = {'encrypted_token': token, 'registration_id': self.registration_id}
            else:
                data = {'token': token}
            oproxy_response = self._http_request('POST',
                                                 '/cdl-token',
                                                 json_data=data,
                                                 timeout=(60 * 3, 60 * 3),
                                                 retries=3,
                                                 backoff_factor=10,
                                                 status_list_to_retry=[400])
        except DemistoException as e:
            if re.match(BAD_REQUEST_REGEX, str(e)):
                demisto.error('The request to retrieve the access token has failed with 400 status code.')
                demisto.setIntegrationContext(self._cache_failure_times(demisto.getIntegrationContext()))
            raise e

        self.reset_failure_times()
        return oproxy_response

    @staticmethod
    def _cache_failure_times(integration_context: dict) -> dict:
        """ Updates the failure times in case of an error with 400 status code.

        Args:
            integration_context: The integration context

        Returns:
            The updated integration context

        """
        current_time = datetime.utcnow().isoformat()
        times_dict = {LAST_FAILURE_TIME_CONST: current_time}
        if not integration_context.get(FIRST_FAILURE_TIME_CONST):
            # first failure
            times_dict[FIRST_FAILURE_TIME_CONST] = current_time
        integration_context.update(times_dict)
        return integration_context

    @staticmethod
    def reset_failure_times():
        """ Resets the time failure counters: FIRST_FAILURE_TIME_CONST & LAST_FAILURE_TIME_CONST

        """
        integration_context = demisto.getIntegrationContext()

        for failure_time_key in (FIRST_FAILURE_TIME_CONST, LAST_FAILURE_TIME_CONST):
            if failure_time_key in integration_context:
                del integration_context[failure_time_key]

        demisto.setIntegrationContext(integration_context)

    def query_loggings(self, query: str, page_number: Optional[str] = None, page_size: Optional[str] = None) \
            -> tuple[list[dict], list]:
        """
        This function handles all the querying of Cortex Logging service

        Args:
            query: The sql string query.
            page_number: The page number to query.
            page_size: The page size to query.

        Returns:
            A list of records according to the query
        """
        query_data = {'query': self.add_instance_id_to_query(query),
                      'language': 'csql'}
        demisto.debug(f'Query being executed in CDL: {str(query_data)}')
        query_service = self.initial_query_service()
        response = query_service.create_query(query_params=query_data, enforce_json=True)
        query_result = response.json()

        if not response.ok:
            status_code = response.status_code
            try:
                # For some error responses the messages are in 'query_result['errors'] and for some they are simply
                # in 'query_result
                errors = query_result.get('errors', query_result)
                error_message = ''.join([message.get('message') for message in errors])
            except AttributeError:
                error_message = query_result

            raise DemistoException(f'Error in query to Cortex Data Lake XSOAR Connector [{status_code}] - {error_message}')
        raw_results = []
        try:
            for r in query_service.iter_job_results(job_id=query_result.get(
                    'jobId'),
                    page_number=arg_to_number(page_number),
                    page_size=arg_to_number(page_size) or 50 if page_number else None,
                    max_wait=2000,
                    result_format='valuesDictionary'):
                raw_results.append(r.json())

        # There is a known issue in iter_job_results where pageCursor and pageNumber are not handled as expected after the first
        # job reaches a 'DONE' status and contains the desired results. This may result in a response with an unexpected
        # status code and missing standard fields, including the 'state' field. The method then attempts to access the 'state'
        # field directly, which can lead to an error. This workaround helps to address the situation.

        except KeyError as e:
            if not e.args[0] == 'state':
                raise DemistoException(f'Received error {str(e)} when querying logs.')
        except exceptions.HTTPError as e:
            raise DemistoException(f'Received error {str(e)} when querying logs.')

        extended_results: list[dict] = []
        for result in raw_results:
            page = result.get('page', {})
            data = page.get('result', {}).get('data', [])
            if data:
                extended_results.extend(data)

        return extended_results, raw_results

    def initial_query_service(self) -> QueryService:
        credentials = Credentials(
            access_token=self.access_token,
            verify=self.use_ssl
        )
        query_service = QueryService(
            url=self.api_url,
            credentials=credentials,
            trust_env=self.trust_env
        )
        return query_service

    def add_instance_id_to_query(self, query: str) -> str:
        """
        On apollo v2 all table names must have the instance_id at the top of their hierarchy.
        This function adds the instance_id to the query.
        For example:
        For the query "SELECT * FROM `test`" with instance_id=1234 this function will return "SELECT * FROM `1234.test`"
        Args:
            query: A query for CDL
        Returns:
            A query with instance_id
        """
        FIND_FROM_STATEMENT_REGEX_PATTERN = r'(?i)FROM `'
        query = re.sub(FIND_FROM_STATEMENT_REGEX_PATTERN, f'FROM `{self.instance_id}.', query)
        return query


''' HELPER FUNCTIONS '''


def human_readable_time_from_epoch_time(epoch_time: int, utc_time: bool = False):
    """
    Divides the epoch time by 1e6 since the epoch format has 6 trailing zeroes
    Since incidents need the time in utc format (ends in 'Z') but the SQL syntax cannot parse a UTC formatted date well
    it is parameterized
    Args:
        utc_time: A boolean that states weather to add the 'Z' at the end of the date string
        epoch_time: Epoch time as it is in the raw_content
    Returns:
        human readable time in the format of '1970-01-01T02:00:00'
    """
    result = datetime.fromtimestamp(epoch_time / 1e6).isoformat() if epoch_time else None
    if result:
        result += 'Z' if utc_time else ''
    return result


def add_milliseconds_to_epoch_time(epoch_time):
    """
    Add 1 millisecond so we would not get duplicate incidents.
    Args:
        epoch_time: Epoch time as it is in the raw_content
    Returns:
        epoch_time with 1 more millisecond.
    """
    epoch_time = int(epoch_time / 1000 + 1) / 1000
    return epoch_time


def epoch_to_timestamp_and_add_milli(epoch_time: int):
    """
    Create human readable time in the format of '1970-01-01T02:00:00.000Z'
    Args:
        epoch_time: Epoch time as it is in the raw_content
    Returns:
        human readable time in the format of '1970-01-01T02:00:00.000Z'
    """
    epoch_time = add_milliseconds_to_epoch_time(epoch_time)
    epoch_time_str = datetime.fromtimestamp(epoch_time).isoformat(timespec='milliseconds') + "Z"
    return epoch_time_str


def common_context_transformer(row_content):
    """
        This function retrieves data from a row of raw data into context path locations

        Args:
            row_content: a dict representing raw data of a row

        Returns:
            a dict with context paths and their corresponding value
        """
    return {
        'Action': row_content.get('action', {}).get('value'),
        'App': row_content.get('app'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'LogSourceName': row_content.get('log_source_name'),
        'IsNat': row_content.get('is_nat'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'AppCategory': row_content.get('app_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'FileSHA256': row_content.get('file_sha_256'),
        'FileName': row_content.get('file_name'),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0))
    }


def system_log_context_transformer(row_content):
    """
    This function retrieves data from a row of raw data into context path locations
    Args:
        row_content: a dict representing raw data of a row
    Returns:
        a dict with context paths and their corresponding value
    """
    return {
        'EventName': row_content.get('event_name'),
        'EventDescription': row_content.get('event_description'),
        'VendorSeverity': row_content.get('severity', ""),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'LogType': row_content.get('log_type', {}).get('value'),
        'LogSourceName': row_content.get('log_source_name')
    }


def traffic_context_transformer(row_content: dict) -> dict:
    """
    This function retrieves data from a row of raw data into context path locations

    Args:
        row_content: a dict representing raw data of a row

    Returns:
        a dict with context paths and their corresponding value
    """

    return {
        'Action': row_content.get('action', {}).get('value'),
        'RiskOfApp': row_content.get('risk_of_app'),
        'NatSourcePort': row_content.get('nat_source_port'),
        'SessionID': row_content.get('session_id'),
        'Packets': row_content.get('packets_total'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'App': row_content.get('app'),
        'Vsys': row_content.get('vsys'),
        'IsNat': row_content.get('is_nat'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'SubcategoryOfApp': row_content.get('app_sub_category'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'DestinationPort': row_content.get('dest_port'),
        'TotalTimeElapsed': row_content.get('total_time_elapsed'),
        'LogSourceName': row_content.get('log_source_name'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'Users': row_content.get('users'),
        'TunneledApp': row_content.get('tunneled_app'),
        'IsPhishing': row_content.get('is_phishing'),
        'SessionEndReason': row_content.get('session_end_reason', {}).get('value'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'SessionStartIP': human_readable_time_from_epoch_time(row_content.get('session_start_time', 0)),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0)),
        'AppCategory': row_content.get('app_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'LogSourceID': row_content.get('log_source_id'),
        'TotalBytes': row_content.get('bytes_total'),
        'VsysID': row_content.get('vsys_id'),
        'ToZone': row_content.get('to_zone'),
        'URLCategory': row_content.get('url_category', {}).get('value'),
        'SourcePort': row_content.get('source_port'),
        'Tunnel': row_content.get('tunnel', {}).get('value'),
        'SourceDeviceHost': row_content.get('source_device_host'),
        'DestDeviceHost': row_content.get('dest_device_host')
    }


def threat_context_transformer(row_content: dict) -> dict:
    """
    This function retrieves data from a row of raw data into context path locations

    Args:
        row_content: a dict representing raw data of a row

    Returns:
        a dict with context paths and their corresponding value
    """
    return {
        'SessionID': row_content.get('session_id'),
        'Action': row_content.get('action', {}).get('value'),
        'App': row_content.get('app'),
        'IsNat': row_content.get('is_nat'),
        'SubcategoryOfApp': row_content.get('app_sub_category'),
        'PcapID': row_content.get('pcap_id'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'Flags': row_content.get('flags'),
        'DestinationPort': row_content.get('dest_port'),
        'ThreatID': row_content.get('threat_id'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'IsURLDenied': row_content.get('is_url_denied'),
        'Users': row_content.get('users'),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0)),
        'IsPhishing': row_content.get('is_phishing'),
        'AppCategory': row_content.get('app_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'ToZone': row_content.get('to_zone'),
        'RiskOfApp': row_content.get('risk_of_app'),
        'NatSourcePort': row_content.get('nat_source_port'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'FromZone': row_content.get('from_zone'),
        'Vsys': row_content.get('vsys'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'ThreatCategory': row_content.get('threat_category', {}).get('value'),
        'ThreatName': row_content.get('threat_name'),
        'LogSourceName': row_content.get('log_source_name'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'Direction': row_content.get('direction_of_attack', {}).get('value'),
        'FileName': row_content.get('file_name'),
        'VendorSeverity': row_content.get('vendor_severity', {}).get('value'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'LogSourceID': row_content.get('log_source_id'),
        'VsysID': row_content.get('vsys_id'),
        'URLDomain': row_content.get('url_domain'),
        'URLCategory': row_content.get('url_category', {}).get('value'),
        'SourcePort': row_content.get('source_port'),
        'FileSHA256': row_content.get('file_sha_256'),
        'SourceDeviceHost': row_content.get('source_device_host'),
        'DestDeviceHost': row_content.get('dest_device_host')
    }


def url_context_transformer(row_content: dict) -> dict:
    """
    This function retrieves data from a row of raw data into context path locations

    Args:
        row_content: a dict representing raw data of a row

    Returns:
        a dict with context paths and their corresponding value
    """

    return {
        'SessionID': row_content.get('session_id'),
        'Action': row_content.get('action', {}).get('value'),
        'App': row_content.get('app'),
        'PcapID': row_content.get('pcap_id'),
        'DestinationPort': row_content.get('dest_port'),
        'AppCategory': row_content.get('app_category'),
        'AppSubcategory': row_content.get('app_sub_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'ToZone': row_content.get('to_zone'),
        'FromZone': row_content.get('from_zone'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'ThreatCategory': row_content.get('threat_category', {}).get('value'),
        'ThreatName': row_content.get('threat_name'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'LogSourceName': row_content.get('log_source_name'),
        'Denied': row_content.get('is_url_denied'),
        'Category': row_content.get('url_category', {}).get('value'),
        'SourcePort': row_content.get('source_port'),
        'URL': row_content.get('url_domain'),
        'URI': row_content.get('uri'),
        'ContentType': row_content.get('content_type'),
        'HTTPMethod': row_content.get('http_method', {}).get('value'),
        'Severity': row_content.get('severity'),
        'UserAgent': row_content.get('user_agent'),
        'RefererProtocol': row_content.get('referer_protocol', {}).get('value'),
        'RefererPort': row_content.get('referer_port'),
        'RefererFQDN': row_content.get('referer_fqdn'),
        'RefererURL': row_content.get('referer_url_path'),
        'SrcUser': row_content.get('source_user'),
        'SrcUserInfo': row_content.get('source_user_info'),
        'DstUser': row_content.get('dest_user'),
        'DstUserInfo': row_content.get('dest_user_info'),
        'TechnologyOfApp': row_content.get('technology_of_app'),
        'SourceDeviceHost': row_content.get('source_device_host'),
        'DestDeviceHost': row_content.get('dest_device_host')
    }


def files_context_transformer(row_content: dict) -> dict:
    """
    This function retrieves data from a row of raw data into context path locations

    Args:
        row_content: a dict representing raw data of a row

    Returns:
        a dict with context paths and their corresponding value
    """

    return {
        'Action': row_content.get('action', {}).get('value'),
        'App': row_content.get('app'),
        'AppCategory': row_content.get('app_category'),
        'AppSubcategory': row_content.get('app_sub_category'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'CloudHostname': row_content.get('cloud_hostname'),
        'CountOfRepeats': row_content.get('count_of_repeats'),
        'CustomerID': row_content.get('customer_id'),
        'DestinationLocation': row_content.get('dest_location'),
        'DestinationPort': row_content.get('dest_port'),
        'DirectionOfAttack': row_content.get('direction_of_attack', {}).get('value'),
        'FileID': row_content.get('file_id'),
        'FileName': row_content.get('file_name'),
        'FileType': row_content.get('file_type'),
        'Flags': row_content.get('flags'),
        'FromZone': row_content.get('from_zone'),
        'Http2Connection': row_content.get('http2_connection'),
        'InboundIf': row_content.get('inbound_if', {}).get('value'),
        'IngestionTime': human_readable_time_from_epoch_time(row_content.get('ingestion_time', 0)),
        'IsCaptivePortal': row_content.get('is_captive_portal'),
        'IsClientToServer': row_content.get('is_client_to_server'),
        'IsContainer': row_content.get('is_container'),
        'IsDecryptMirror': row_content.get('is_decrypt_mirror'),
        'IsDupLog': row_content.get('is_dup_log'),
        'IsExported': row_content.get('is_exported'),
        'IsForwarded': row_content.get('is_forwarded'),
        'IsMptcpOn': row_content.get('is_mptcp_on'),
        'IsNat': row_content.get('is_nat'),
        'IsNonStdDestPort': row_content.get('is_non_std_dest_port'),
        'IsPacketCapture': row_content.get('is_packet_capture'),
        'IsPhishing': row_content.get('is_phishing'),
        'IsPrismaBranch': row_content.get('is_prisma_branch'),
        'IsPrismaMobile': row_content.get('is_prisma_mobile'),
        'IsProxy': row_content.get('is_proxy'),
        'IsReconExcluded': row_content.get('is_recon_excluded'),
        'IsSaasApp': row_content.get('is_saas_app'),
        'IsServerToClient': row_content.get('is_server_to_client'),
        'IsSymReturn': row_content.get('is_sym_return'),
        'IsTransaction': row_content.get('is_transaction'),
        'IsTunnelInspected': row_content.get('is_tunnel_inspected'),
        'IsUrlDenied': row_content.get('is_url_denied'),
        'LogSet': row_content.get('log_set'),
        'LogSource': row_content.get('log_source'),
        'LogSourceID': row_content.get('log_source_id'),
        'LogSourceName': row_content.get('log_source_name'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'LogType': row_content.get('log_type', {}).get('value'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'NatSourcePort': row_content.get('nat_source_port'),
        'OutboundIf': row_content.get('outbound_if', {}).get('value'),
        'PcapID': row_content.get('pcap_id'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'RecordSize': row_content.get('record_size'),
        'ReportID': row_content.get('report_id'),
        'RiskOfApp': row_content.get('risk_of_app'),
        'RuleMatched': row_content.get('rule_matched'),
        'RuleMatchedUuid': row_content.get('rule_matched_uuid'),
        'SanctionedStateOfApp': row_content.get('sanctioned_state_of_app'),
        'SequenceNo': row_content.get('sequence_no'),
        'SessionID': row_content.get('session_id'),
        'Severity': row_content.get('severity'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'TechnologyOfApp': row_content.get('technology_of_app'),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0)),
        'ToZone': row_content.get('to_zone'),
        'Tunnel': row_content.get('tunnel', {}).get('value'),
        'TunneledApp': row_content.get('tunneled_app'),
        'URLCategory': row_content.get('url_category', {}).get('value'),
        'FileSHA256': row_content.get('file_sha_256'),
        'Vsys': row_content.get('vsys'),
        'VsysID': row_content.get('vsys_id'),
        'VendorName': row_content.get('vendor_name'),
        'VendorSeverity': row_content.get('vendor_severity', {}).get('value')
    }


def gp_context_transformer(row_content: dict) -> dict:
    """
        This function retrieves data from a row of raw data into context path locations.
        Documentation: https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-globalprotect-log

        Args:
            row_content: a dict representing raw data of a row

        Returns:
            a dict with context paths and their corresponding value
        """
    return {
        'AttemptedGateways': row_content.get('attempted_gateways'),
        'AuthMethod': row_content.get('auth_method'),
        'ConnectMethod': row_content.get('connect_method'),
        'ConnectionErrorID': row_content.get('connection_error', {}).get('id'),
        'ConnectionErrorValue': row_content.get('connection_error', {}).get('value'),
        'CountOfRepeats': row_content.get('count_of_repeats'),
        'CustomerID': row_content.get('customer_id'),
        'EndpointDeviceName': row_content.get('endpoint_device_name'),
        'EndpointGPVersion': row_content.get('endpoint_gp_version'),
        'EndpointOSType': row_content.get('endpoint_os_type'),
        'EndpointOSVersion': row_content.get('endpoint_os_version'),
        'EndpointSN': row_content.get('endpoint_serial_number'),
        'EventID': row_content.get('event_id', {}).get('value'),
        'Gateway': row_content.get('gateway'),
        'GatewayPriority': row_content.get('gateway_priority', {}).get('value'),
        'GatewaySelectionType': row_content.get('gateway_selection_type'),
        'GPGatewayLocation': row_content.get('gpg_location'),
        'HostID': row_content.get('host_id'),
        'IsDuplicateLog': row_content.get('is_dup_log'),
        'IsExported': row_content.get('is_exported'),
        'IsForwarded': row_content.get('is_forwarded'),
        'IsPrismaBranch': row_content.get('is_prisma_branch'),
        'IsPrismaMobile': row_content.get('is_prisma_mobile'),
        'LogSource': row_content.get('log_source'),
        'LogSourceID': row_content.get('log_source_id'),
        'LogSourceName': row_content.get('log_source_name'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'LogType': row_content.get('log_type', {}).get('value'),
        'LoginDuration': row_content.get('login_duration'),
        'Opaque': row_content.get('opaque'),
        'PanoramaSN': row_content.get('panorama_serial'),
        'PlatformType': row_content.get('platform_type'),
        'Portal': row_content.get('portal'),
        'PrivateIPv4': row_content.get('private_ip', {}).get('value'),
        'PrivateIPv6': row_content.get('private_ipv6', {}).get('value'),
        'ProjectName': row_content.get('project_name'),
        'PublicIPv4': row_content.get('public_ip', {}).get('value'),
        'PublicIPv6': row_content.get('public_ipv6', {}).get('value'),
        'QuarantineReason': row_content.get('quarantine_reason'),
        'SequenceNo': row_content.get('sequence_no'),
        'SourceRegion': row_content.get('source_region'),
        'SourceUser': row_content.get('source_user'),
        'SourceUserDomain': row_content.get('source_user_info', {}).get('domain'),
        'SourceUserName': row_content.get('source_user_info', {}).get('name'),
        'SourceUserUUID': row_content.get('source_user_info', {}).get('uuid'),
        'SSLResponseTime': row_content.get('ssl_response_time'),
        'Stage': row_content.get('stage'),
        'EventStatus': row_content.get('status', {}).get('value'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0)),
        'TunnelType': row_content.get('tunnel'),
        'VendorName': row_content.get('vendor_name'),
    }


def records_to_human_readable_output(fields: str, table_name: str, results: list) -> str:
    """
    This function gets all relevant data for the human readable output of a specific table.
    By design if the user queries all fields of the table (i.e. enters '*' in the query) than the outputs
    shown in the war room will be the same for each query - the outputs will be the headers list in the code.
    If the user selects different fields in the query than those fields will be shown to the user.

    Args:
        fields: The field of the table named table_name
        table_name: The name of the table
        results: The results needs to be shown

    Returns:
        A markdown table of the outputs
    """
    filtered_results: list = []

    if fields == '*':
        for result in results:
            filtered_result = {
                'Source Address': result.get('source_ip', {}).get('value'),
                'Destination Address': result.get('dest_ip', {}).get('value'),
                'Application': result.get('app'),
                'Action': result.get('action', {}).get('value'),
                'RuleMatched': result.get('rule_matched'),
                'TimeGenerated': human_readable_time_from_epoch_time(result.get('time_generated')),
                'FileID': result.get('file_id'),
                'FileName': result.get('file_name'),
                'FileType': result.get('file_type')
            }
            filtered_results.append(filtered_result)
    else:
        for result in results:
            filtered_result = {}
            for root in result:
                parsed_tree: dict = parse_tree_by_root_to_leaf_paths(root, result[root])
                filtered_result.update(parsed_tree)
            filtered_results.append(filtered_result)

    return tableToMarkdown(f'Logs {table_name} table', filtered_results, removeNull=True)


def parse_tree_by_root_to_leaf_paths(root: str, body) -> dict:
    """
    This function receives a dict (root and a body) and parses it according to the upcoming example:
    Input: root = 'a', body = {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}.
    So the dict is {'a': {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}}
    The expected output is {'a.b': 2, 'a.c': 3, 'a.d.e': 5, 'a.d.f': 6, 'a.d.g.h': 8, 'a.d.g.i': 9}
    Basically what this function does is when it gets a tree it creates a dict from it which it's keys are all
    root to leaf paths and the corresponding values are the values in the leafs
    Please note that the implementation is similar to DFS on trees (which means we don't have to check for visited
    nodes since there are no cycles)

    Args:
        root: The root string
        body: The body of the root

    Returns:
        The parsed tree
    """
    parsed_tree: dict = {}
    help_stack: list = [(root, body)]

    while help_stack:
        node: tuple = help_stack.pop()
        root_to_node_path: str = node[0]
        body = node[1]
        if isinstance(body, dict):
            for key, value in body.items():
                # for each node we append a tuple of it's body and the path from the root to it
                help_stack.append((root_to_node_path + '.' + key, value))
        elif isinstance(body, list):
            for element in body:
                help_stack.append((root_to_node_path, element))
        else:
            parsed_tree[root_to_node_path] = body
    return parsed_tree


def build_where_clause(args: dict) -> str:
    """
    This function transforms the relevant entries of dict into the where part of a SQL query

    Args:
        args: The arguments dict

    Returns:
        A string represents the where part of a SQL query
    """
    args_dict = {
        'source_ip': 'source_ip.value',
        'dest_ip': 'dest_ip.value',
        'rule_matched': 'rule_matched',
        'from_zone': 'from_zone',
        'to_zone': 'to_zone',
        'source_port': 'source_port',
        'dest_port': 'dest_port',
        'action': 'action.value',
        'file_sha_256': 'file_sha_256',
        'file_name': 'file_name',
        'app': 'app',
        'app_category': 'app_category',
        'dest_device_port': 'dest_device_port',
        'dest_edl': 'dest_edl',
        'dest_dynamic_address_group': 'dest_dynamic_address_group',
        'dest_location': 'dest_location',
        'dest_user': 'dest_user',
        'file_type': 'file_type',
        'is_server_to_client': 'is_server_to_client',
        'is_url_denied': 'is_url_denied',
        'log_type': 'log_type',
        'nat_dest': 'nat_dest',
        'nat_dest_port': 'nat_dest_port',
        'nat_source': 'nat_source',
        'nat_source_port': 'nat_source_port',
        'rule_matched_uuid': 'rule_matched_uuid',
        'severity': 'severity',
        'source_device_host': 'source_device_host',
        'source_edl': 'source_edl',
        'source_dynamic_address_group': 'source_dynamic_address_group',
        'source_location': 'source_location',
        'source_user': 'source_user',
        'sub_type': 'sub_type.value',
        'time_generated': 'time_generated',
        'url_category': 'url_category',
        'url_domain': 'url_domain',
        'event_name': 'event_id.value',
        'gateway': 'gateway',
        'private_ipv4': 'private_ip.value',
        'private_ipv6': 'private_ipv6.value',
        'public_ipv4': 'public_ip.value',
        'public_ipv6': 'public_ipv6.value',
        'event_status': 'status.value',
        'portal': 'portal'

    }
    if args.get('ip') and (args.get('source_ip') or args.get('dest_ip')):
        raise DemistoException('Error: "ip" argument cannot appear with either "source_ip" nor "dest_ip"')

    if args.get('port') and (args.get('source_port') or args.get('dest_port')):
        raise DemistoException('Error: "port" argument cannot appear with either "source_port" nor "dest_port"')

    non_string_keys = {'dest_port', 'source_port'}
    if 'query' in args:
        # if query arg is supplied than we just need to parse it and only it
        return args['query'].strip()

    where_clause = ''
    if args.get('ip'):
        ips = argToList(args.pop('ip'))
        # Creating a query for ip argument using source ip and dest ip
        where_clause += '(' + ' OR '.join(f'source_ip.value = "{ip}" OR dest_ip.value = "{ip}"' for ip in ips) + ')'
        if any(args.get(key) for key in args_dict) or args.get('port') or args.get('url'):
            where_clause += ' AND '

    if args.get('port'):
        ports = argToList(args.pop('port'))
        # Creating a query for port argument using source port and dest port
        where_clause += '(' + ' OR '.join(f'source_port = {port} OR dest_port = {port}' for port in ports) + ')'
        if any(args.get(key) for key in args_dict):
            where_clause += ' AND '

    if args.get('url'):
        urls = argToList(args.pop('url'))
        # Creating a query for url argument using uri and referer
        where_clause += '(' + ' OR '.join(f'uri LIKE "%{url}%" OR referer LIKE "%{url}%"' for url in urls) + ')'
        if any(args.get(key) for key in args_dict):
            where_clause += ' AND '

    if args.get('rule'):
        rules_list = argToList(args.pop('rule'))
        where_clause += '(' + ' OR '.join(f'rule_matched = "{rule}"' for rule in rules_list) + ')'
        if any(args.get(key) for key in args_dict):
            where_clause += ' AND '

    # We want to add only keys that are part of the query
    string_query_fields = {key: value for key, value in args.items() if key in args_dict and key not in non_string_keys}
    or_statements = []
    for key, values in string_query_fields.items():
        string_values_list: list = argToList(values)
        field = args_dict[key]
        or_statements.append(' OR '.join([f'{field} = "{value}"' for value in string_values_list]))
    # ports are digested as ints and cannot be sent as strings
    non_string_query_fields = {key: value for key, value in args.items() if key in non_string_keys}
    for key, values in non_string_query_fields.items():
        non_string_values_list: list = argToList(values)
        field = args_dict[key]
        or_statements.append(' OR '.join([f'{field} = {value}' for value in non_string_values_list]))
    where_clause += ' AND '.join([f'({or_statement})' for or_statement in or_statements if or_statement])
    return where_clause


def get_encrypted(auth_id: str, key: str) -> str:
    """

    Args:
        auth_id (str): auth_id from oproxy
        key (str): key from oproxy

    Returns:
        The encrypted auth_id with the time it was encrypted using AESGCM algorithm
    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        decoded_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(decoded_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)

    now = int(time.time())
    return encrypt(f'{now}:{auth_id}', key).decode('utf-8')


def prepare_fetch_incidents_query(fetch_timestamp: str,
                                  fetch_severity: list,
                                  fetch_table: str,
                                  fetch_subtype: list,
                                  fetch_fields: str,
                                  fetch_limit: str,
                                  fetch_filter: str = '') -> str:
    """
    Prepares the SQL query for fetch incidents command
    Args:
        fetch_limit: Indicates how many incidents should be queried
        fetch_timestamp: The date from which threat logs should be queried
        fetch_severity: Severity associated with the incident.
        fetch_subtype: Identifies the log subtype.
        fetch_table: Identifies the fetch type.
        fetch_fields: Fields to fetch from the table.
        fetch_filter: Filter that should be used for the query.

    Returns:
        SQL query that matches the arguments
    """
    if fetch_filter and (fetch_subtype or fetch_severity):
        raise DemistoException('Fetch Filter parameter cannot be used with Subtype/Severity parameters.')
    query = f'SELECT {fetch_fields} FROM `{fetch_table}` '  # guardrails-disable-line # noqa: S608
    time_filter = 'event_time' if 'log' in fetch_table else 'time_generated'
    query += f'WHERE {time_filter} Between TIMESTAMP("{fetch_timestamp}") ' \
             f'AND CURRENT_TIMESTAMP'
    if fetch_filter:
        query += f' AND {fetch_filter}'
    if fetch_subtype and 'all' not in fetch_subtype:
        sub_types = [f'sub_type.value = "{sub_type}"' for sub_type in fetch_subtype]
        query += f' AND ({" OR ".join(sub_types)})'
    if fetch_severity and 'all' not in fetch_severity:
        severities = [f'vendor_severity.value = "{severity}"' for severity in fetch_severity]
        query += f' AND ({" OR ".join(severities)})'
    query += f' ORDER BY {time_filter} ASC LIMIT {fetch_limit}'
    return query


def convert_log_to_incident(log: dict, fetch_table: str) -> dict:
    time_filter = 'event_time' if 'log' in fetch_table else 'time_generated'
    time_generated = log.get(time_filter, 0)
    occurred = human_readable_time_from_epoch_time(time_generated, utc_time=True)
    incident = {
        'name': FETCH_TABLE_HR_NAME[fetch_table],
        'rawJSON': json.dumps(log, ensure_ascii=False),
        'occurred': occurred
    }
    return incident


''' COMMANDS FUNCTIONS '''


def test_module(client: Client, fetch_table, fetch_fields, is_fetch, fetch_query, fetch_subtype, fetch_severity, first_fetch):
    if is_fetch:
        fetch_time, _ = parse_date_range(first_fetch)
        fetch_time = fetch_time.replace(microsecond=0)
        query = prepare_fetch_incidents_query(fetch_time, fetch_severity, fetch_table,
                                              fetch_subtype, fetch_fields, "1", fetch_query)
    else:
        # fetch params not to be tested (won't be used)
        fetch_fields = '*'
        fetch_table = 'firewall.traffic'
        query = f'SELECT {fetch_fields} FROM `{fetch_table}` limit 1'  # noqa: S608
    client.query_loggings(query)
    return_outputs('ok')


def query_logs_command(args: dict, client: Client) -> tuple[str, dict[str, list[dict]], list[dict[str, Any]]]:
    """
    Return the result of querying the Logging service
    """
    query = args.get('query', '')
    limit = args.get('limit', '')
    transform_results = argToBoolean(args.get('transform_results', 'true'))

    if not args.get('page') and 'limit' not in query.lower():
        query += f' LIMIT {limit}'

    records, raw_results = client.query_loggings(query, page_number=args.get('page'), page_size=args.get('page_size'))

    table_name = get_table_name(query)
    output_results = records
    if transform_results:
        output_results = [
            system_log_context_transformer(record) if 'log.system' in query else common_context_transformer(record) for
            record in records]
    human_readable = tableToMarkdown('Logs ' + table_name + ' table', output_results, removeNull=True)
    ec = {
        'CDL.Logging': output_results
    }
    return human_readable, ec, raw_results


def get_table_name(query: str) -> str:
    """
    Table name is stored in log_type attribute of the records
    Args:
        query: Query string, i.e SELECT * FROM firewall.threat LIMIT 1

    Returns:
        The query's table name
    """
    find_table_name_from_query = r'(FROM `)(\w+.\w+)(`)'
    search_result = re.search(find_table_name_from_query, query)
    if search_result:
        return search_result.group(2)
    return "Unrecognized table name"


def get_critical_logs_command(args: dict, client: Client) -> tuple[str, dict[str, list[dict]], list[dict[str, Any]]]:
    """
    Queries Cortex Logging according to a pre-set query
    """
    logs_amount = args.get('limit')
    query_start_time, query_end_time = query_timestamp(args)
    query = 'SELECT * FROM `firewall.threat` WHERE severity = "Critical" '  # guardrails-disable-line
    query += f'AND time_generated BETWEEN TIMESTAMP("{query_start_time}") AND ' \
             f'TIMESTAMP("{query_end_time}")'

    if not args.get('page'):
        query += f' LIMIT {logs_amount}'

    records, raw_results = client.query_loggings(query, page_number=args.get('page'), page_size=args.get('page_size'))

    transformed_results = [threat_context_transformer(record) for record in records]

    human_readable = tableToMarkdown('Logs threat table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging.Threat': transformed_results
    }
    return human_readable, ec, raw_results


def query_timestamp(args: dict) -> tuple[datetime, datetime]:
    start_time = args.get('start_time', '')
    end_time = args.get('end_time', '')
    time_range = args.get('time_range', '')
    if time_range:
        query_start_time, query_end_time = parse_date_range(time_range)
    else:
        # parses user input to datetime object
        query_start_time = parser.parse(start_time)
        # if end_time is not given- will be replaced with current time
        query_end_time = parser.parse(end_time) if end_time else datetime.fromtimestamp(time.time())
    return query_start_time.replace(microsecond=0), query_end_time.replace(microsecond=0)


def get_social_applications_command(args: dict,
                                    client: Client) -> tuple[str, dict[str, list[dict]], list[dict[str, Any]]]:
    """ Queries Cortex Logging according to a pre-set query """
    logs_amount = args.get('limit')
    query_start_time, query_end_time = query_timestamp(args)
    query = 'SELECT * FROM `firewall.traffic` WHERE app_sub_category = "social-networking" '  # guardrails-disable-line
    query += f' AND time_generated BETWEEN TIMESTAMP("{query_start_time}") AND ' \
             f'TIMESTAMP("{query_end_time}")'

    if not args.get('page'):
        query += f' LIMIT {logs_amount}'

    records, raw_results = client.query_loggings(query, page_number=args.get('page'), page_size=args.get('page_size'))

    transformed_results = [traffic_context_transformer(record) for record in records]

    human_readable = tableToMarkdown('Logs traffic table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging.Traffic': transformed_results
    }
    return human_readable, ec, raw_results


def search_by_file_hash_command(args: dict, client: Client) -> tuple[str, dict[str, list[dict]], list[dict[str, Any]]]:
    """
    Queries Cortex Logging according to a pre-set query
    """
    logs_amount = args.get('limit')
    file_hash = args.get('SHA256')

    query_start_time, query_end_time = query_timestamp(args)
    query = f'SELECT * FROM `firewall.threat` WHERE file_sha_256 = "{file_hash}" '  # guardrails-disable-line  # noqa: S608
    query += f'AND time_generated BETWEEN TIMESTAMP("{query_start_time}") AND ' \
             f'TIMESTAMP("{query_end_time}")'

    if not args.get('page'):
        query += f' LIMIT {logs_amount}'

    records, raw_results = client.query_loggings(query, page_number=args.get('page'), page_size=args.get('page_size'))

    transformed_results = [threat_context_transformer(record) for record in records]

    human_readable = tableToMarkdown('Logs threat table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging.Threat': transformed_results
    }
    return human_readable, ec, raw_results


def query_traffic_logs_command(args: dict, client: Client) -> tuple[str, dict, list[dict[str, Any]]]:
    """
    The function of the command that queries firewall.traffic table

        Returns: a Demisto's entry with all the parsed data
    """
    table_name: str = 'traffic'
    context_transformer_function = traffic_context_transformer
    table_context_path: str = 'CDL.Logging.Traffic'
    return query_table_logs(args, client, table_name, context_transformer_function, table_context_path)


def query_threat_logs_command(args: dict, client: Client) -> tuple[str, dict, list[dict[str, Any]]]:
    """
    The function of the command that queries firewall.threat table

        Returns: a Demisto's entry with all the parsed data
    """
    query_table_name: str = 'threat'
    context_transformer_function = threat_context_transformer
    table_context_path: str = 'CDL.Logging.Threat'
    return query_table_logs(args, client, query_table_name, context_transformer_function, table_context_path)


def query_url_logs_command(args: dict, client: Client) -> tuple[str, dict, list[dict[str, Any]]]:
    """
    The function of the command that queries firewall.url table

        Returns: a Demisto's entry with all the parsed data
    """
    query_table_name: str = 'url'
    context_transformer_function = url_context_transformer
    table_context_path: str = 'CDL.Logging.URL'
    return query_table_logs(args, client, query_table_name, context_transformer_function, table_context_path)


def query_file_data_command(args: dict, client: Client) -> tuple[str, dict, list[dict[str, Any]]]:
    query_table_name: str = 'file_data'
    context_transformer_function = files_context_transformer
    table_context_path: str = 'CDL.Logging.File'
    return query_table_logs(args, client, query_table_name, context_transformer_function, table_context_path)


def query_gp_logs_command(args: dict, client: Client):
    """
    The function of the command that queries firewall.globalprotect table

        Returns: a Demisto's entry with all the parsed data
    """
    table_name: str = 'globalprotect'
    context_transformer_function = gp_context_transformer
    table_context_path: str = 'CDL.Logging.GlobalProtect'
    return query_table_logs(args, client, table_name, context_transformer_function, table_context_path)


def query_table_logs(args: dict,
                     client: Client,
                     table_name: str,
                     context_transformer_function: Callable[[dict], dict],
                     table_context_path: str) -> tuple[str, dict, list[dict[str, Any]]]:
    """
    This function is a generic function that get's all the data needed for a specific table of Cortex and acts as a
    regular command function

    Args:
        args: demisto args
        client: The client
        table_name: the name of the table in Cortex
        context_transformer_function:  the context transformer function to parse the data
        table_context_path: the context path where the parsed data should be located
    """
    fields, query = build_query(args, table_name)
    results, raw_results = client.query_loggings(query, page_number=args.get('page'), page_size=args.get('page_size'))
    outputs = [context_transformer_function(record) for record in results]
    human_readable = records_to_human_readable_output(fields, table_name, results)

    context_outputs: dict = {table_context_path: outputs}
    return human_readable, context_outputs, raw_results


def build_query(args, table_name):
    fields = args.get('fields', 'all')
    fields = '*' if 'all' in fields else fields
    where = build_where_clause(args)
    query_start_time, query_end_time = query_timestamp(args)
    timestamp_limitation = f'time_generated BETWEEN TIMESTAMP("{query_start_time}") AND ' \
                           f'TIMESTAMP("{query_end_time}") '
    where += f' AND {timestamp_limitation}' if where else timestamp_limitation
    query = f'SELECT {fields} FROM `firewall.{table_name}` WHERE {where}'  # noqa: S608
    if not args.get('page'):
        limit = args.get('limit', '5')
        query += f' LIMIT {limit}'
    return fields, query


def fetch_incidents(client: Client,
                    first_fetch_timestamp: str,
                    fetch_severity: list,
                    fetch_table: str,
                    fetch_subtype: list,
                    fetch_fields: str,
                    fetch_limit: str,
                    last_run: dict,
                    fetch_filter: str = '') -> tuple[dict[str, str], list]:
    last_fetched_event_timestamp = last_run.get('lastRun')
    demisto.debug("CortexDataLake - Start fetching")
    demisto.debug(f"CortexDataLake - Last run: {json.dumps(last_run)}")

    if last_fetched_event_timestamp:
        last_fetched_event_timestamp = parser.parse(last_fetched_event_timestamp)
    else:
        last_fetched_event_timestamp, _ = parse_date_range(first_fetch_timestamp)
        last_fetched_event_timestamp = last_fetched_event_timestamp.replace(microsecond=0)
    query = prepare_fetch_incidents_query(last_fetched_event_timestamp, fetch_severity, fetch_table,
                                          fetch_subtype, fetch_fields, fetch_limit, fetch_filter)
    demisto.debug(f"CortexDataLake - Query sent to the server: {query}")
    records, _ = client.query_loggings(query)
    if not records:
        return {'lastRun': str(last_fetched_event_timestamp)}, []

    incidents = [convert_log_to_incident(record, fetch_table) for record in records]
    time_filter = 'event_time' if 'log' in fetch_table else 'time_generated'
    max_fetched_event_timestamp = max(records, key=lambda record: record.get(time_filter, 0)).get(time_filter, 0)

    next_run = {'lastRun': epoch_to_timestamp_and_add_milli(max_fetched_event_timestamp)}
    demisto.debug(f'CortexDataLake - Next run after incidents fetching: {json.dumps(next_run)}')
    demisto.debug(f"CortexDataLake- Number of incidents before filtering: {len(records)}")
    demisto.debug(f"CortexDataLake - Number of incidents after filtering: {len(incidents)}")
    return next_run, incidents


''' EXECUTION CODE '''


def main():
    os.environ['PAN_CREDENTIALS_DBFILE'] = os.path.join(gettempdir(), 'pancloud_credentials.json')
    params = demisto.params()
    registration_id_and_url = params.get('credentials_reg_id', {}).get('password') or params.get('reg_id')
    # If there's a stored token in integration context, it's newer than current
    refresh_token = params.get('credentials_refresh_token', {}).get('password') or params.get('refresh_token')
    enc_key = params.get('credentials_auth_key', {}).get('password') or params.get('auth_key')
    if not enc_key or not refresh_token or not registration_id_and_url:
        raise DemistoException('Key, Token and ID must be provided.')
    # is_fr = ('federal.paloaltonetworks.com' in demisto.getLicenseCustomField('Http_Connector.url'))
    is_fr = False
    demisto.debug(f"working on tenant with {is_fr=}")
    registration_id_and_url = registration_id_and_url.split('@')
    if len(registration_id_and_url) != 2:
        if is_fr:
            token_retrieval_url = "https://cortex-gateway-federal.paloaltonetworks.com/api/xdr_gateway/external_services/cdl"
        else:
            token_retrieval_url = "https://oproxy.demisto.ninja"  # guardrails-disable-line
    else:
        token_retrieval_url = registration_id_and_url[1]
    registration_id = registration_id_and_url[0]
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    args = demisto.args()
    fetch_table = params.get('fetch_table')
    fetch_fields = params.get('fetch_fields') or '*'
    command = demisto.command()
    LOG(f'command is {command}')
    # needs to be executed before creating a Client
    if command == 'cdl-reset-authentication-timeout':
        Client.reset_failure_times()
        return_outputs(readable_output="Caching mechanism failure time counters have been successfully reset.")
        return

    client = Client(token_retrieval_url, registration_id, use_ssl, proxy, refresh_token, enc_key, is_fr)

    try:
        if command == 'test-module':
            test_module(client, fetch_table, fetch_fields, params.get('isFetch'), params.get('filter_query', ''),
                        params.get('firewall_subtype'), params.get('firewall_severity'),
                        params.get('first_fetch_timestamp', '24 hours').strip())
        elif command == 'cdl-query-logs':
            return_outputs(*query_logs_command(args, client))
        elif command == 'cdl-get-critical-threat-logs':
            return_outputs(*get_critical_logs_command(args, client))
        elif command == 'cdl-get-social-applications':
            return_outputs(*get_social_applications_command(args, client))
        elif command == 'cdl-search-by-file-hash':
            return_outputs(*search_by_file_hash_command(args, client))
        elif command == 'cdl-query-traffic-logs':
            return_outputs(*query_traffic_logs_command(args, client))
        elif command == 'cdl-query-threat-logs':
            return_outputs(*query_threat_logs_command(args, client))
        elif command == 'cdl-query-url-logs':
            return_outputs(*query_url_logs_command(args, client))
        elif command == 'cdl-query-file-data':
            return_outputs(*query_file_data_command(args, client))
        elif command == 'cdl-query-gp-logs':
            return_outputs(*query_gp_logs_command(args, client))
        elif command == 'fetch-incidents':
            first_fetch_timestamp = params.get('first_fetch_timestamp', '24 hours').strip()
            fetch_severity = params.get('firewall_severity')
            fetch_table = params.get('fetch_table')
            fetch_fields = params.get('fetch_fields') or '*'
            fetch_subtype = params.get('firewall_subtype')
            fetch_limit = params.get('limit')
            last_run = demisto.getLastRun()
            fetch_filter = params.get('filter_query', '')
            next_run, incidents = fetch_incidents(client,
                                                  first_fetch_timestamp,
                                                  fetch_severity,
                                                  fetch_table,
                                                  fetch_subtype,
                                                  fetch_fields,
                                                  fetch_limit,
                                                  last_run,
                                                  fetch_filter)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
    except Exception as e:
        error_message = str(e)
        return_error(error_message)


if __name__ in ('__main__', 'builtins'):
    main()
