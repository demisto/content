import base64
import json
import re
from typing import Dict, List, Optional, Set, Tuple

import demistomock as demisto  # noqa: F401
import jwt
import requests
from CommonServerPython import *  # noqa: F401
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
APP_NAME = 'ms-management-api'
PUBLISHER_IDENTIFIER = 'ebac1a16-81bf-449b-8d43-5732c3c1d999'  # This isn't a secret and is public knowledge.

CONTENT_TYPE_TO_TYPE_ID_MAPPING = {
    'ExchangeAdmin': 1,
    'ExchangeItem': 2,
    'ExchangeItemGroup': 3,
    'SharePoint': 4,
    'SharePointFileOperation': 6,
    'AzureActiveDirectory': 8,
    'AzureActiveDirectoryAccountLogon': 9,
    'DataCenterSecurityCmdlet': 10,
    'ComplianceDLPSharePoint': 11,
    'Sway': 12,
    'ComplianceDLPExchange': 13,
    'SharePointSharingOperation': 14,
    'AzureActiveDirectoryStsLogon': 15,
    'SecurityComplianceCenterEOPCmdlet': 18,
    'PowerBIAudit': 20,
    'CRM': 21,
    'Yammer': 22,
    'SkypeForBusinessCmdlets': 23,
    'Discovery': 24,
    'MicrosoftTeams': 25,
    'ThreatIntelligence': 28,
    'MailSubmission': 29,
    'MicrosoftFlow': 30,
    'AeD': 31,
    'MicrosoftStream': 32,
    'ComplianceDLPSharePointClassification': 33,
    'Project': 35,
    'SharePointListOperation': 36,
    'DataGovernance': 38,
    'SecurityComplianceAlerts': 40,
    'ThreatIntelligenceUrl': 41,
    'SecurityComplianceInsights': 42,
    'WorkplaceAnalytics': 44,
    'PowerAppsApp': 45,
    'ThreatIntelligenceAtpContent': 47,
    'TeamsHealthcare': 49,
    'DataInsightsRestApiAudit': 52,
    'SharePointListItemOperation': 54,
    'SharePointContentTypeOperation': 55,
    'SharePointFieldOperation': 56,
    'AirInvestigation': 64,
    'Quarantine': 65,
    'MicrosoftForms': 66
}
# Transferring content types to lowercase to prevent user errors (such as 'quarantine' instead of 'Quarantine')
CONTENT_TYPE_TO_TYPE_ID_MAPPING = {key.lower(): value for key, value in CONTENT_TYPE_TO_TYPE_ID_MAPPING.items()}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str, verify: bool,
                 proxy: bool, self_deployed, refresh_token, auth_and_token_url,
                 enc_key, auth_code, tenant_id, redirect_uri):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.tenant_id = tenant_id
        self.suffix_template = '{}/activity/feed/subscriptions/{}'
        self.access_token = None
        self.self_deployed = self_deployed
        self.refresh_token = refresh_token
        self.auth_and_token_url = auth_and_token_url
        self.enc_key = enc_key
        self.ms_client = MicrosoftClient(self_deployed=self.self_deployed,
                                         tenant_id=self.tenant_id,
                                         auth_id=self.auth_and_token_url,
                                         enc_key=self.enc_key,
                                         app_name=APP_NAME,
                                         base_url=base_url,
                                         grant_type=AUTHORIZATION_CODE,
                                         verify=verify,
                                         proxy=proxy,
                                         refresh_token=self.refresh_token,
                                         ok_codes=(200, 201, 202, 204),
                                         scope='',
                                         auth_code=auth_code,
                                         resource='https://manage.office.com',
                                         token_retrieval_url='https://login.windows.net/common/oauth2/token',
                                         redirect_uri=redirect_uri)

    def get_access_token_data(self):
        access_token_jwt = self.ms_client.get_access_token()
        token_data = jwt.decode(access_token_jwt, options={'verify_signature': False})
        return access_token_jwt, token_data

    def get_authentication_string(self):
        return f'Bearer {self.access_token}'

    def get_blob_data_request(self, blob_url, timeout=10):
        '''
        Args:
            blob_url: The URL for the blob.
            timeout: Timeout for http request.
            The default timeout in the Client class is 10 seconds. That's why the defualt here is 10 as well.
        '''
        auth_string = self.get_authentication_string()
        headers = {
            'Content-Type': 'application/json',
            'Authorization': auth_string
        }
        params = {
            'PublisherIdentifier': PUBLISHER_IDENTIFIER
        }
        response = self._http_request(
            method='GET',
            url_suffix='',
            full_url=blob_url,
            headers=headers,
            params=params,
            timeout=timeout,
        )
        return response

    def list_content_request(self, content_type, start_time, end_time, timeout=10):
        """
        Args:
            content_type: the content type
            start_time: start time to fetch content
            end_time: end time to fetch content
            timeout: Timeout for http request.
            The default timeout in the Client class is 10 seconds. That's why the defualt here is 10 as well.
        """
        auth_string = self.get_authentication_string()
        headers = {
            'Authorization': auth_string
        }
        params = {
            'PublisherIdentifier': PUBLISHER_IDENTIFIER,
            'contentType': content_type
        }

        if start_time and end_time:
            params['startTime'] = start_time
            params['endTime'] = end_time

        response = self._http_request(
            method='GET',
            url_suffix=self.suffix_template.format(self.tenant_id, 'content'),
            headers=headers,
            params=params,
            timeout=timeout,
        )
        return response

    def list_subscriptions_request(self):
        auth_string = self.get_authentication_string()
        headers = {
            'Authorization': auth_string
        }
        params = {
            'PublisherIdentifier': PUBLISHER_IDENTIFIER
        }
        response = self._http_request(
            method='GET',
            url_suffix=self.suffix_template.format(self.tenant_id, 'list'),
            headers=headers,
            params=params
        )
        return response

    def start_or_stop_subscription_request(self, content_type, start_or_stop_suffix):

        auth_string = self.get_authentication_string()
        headers = {
            'Authorization': auth_string
        }
        params = {
            'PublisherIdentifier': PUBLISHER_IDENTIFIER,
            'contentType': content_type
        }
        return self._http_request(
            method='POST',
            url_suffix=self.suffix_template.format(self.tenant_id, start_or_stop_suffix),
            headers=headers,
            params=params,
            ok_codes=(200, 201, 202, 203, 204),
            return_empty_response=True
        )


def test_module():
    params = demisto.params()
    fetch_delta = params.get('first_fetch_delta', '10 minutes')
    user_input_fetch_start_date, _ = parse_date_range(fetch_delta)
    if datetime.now() - timedelta(days=7) - timedelta(minutes=5) >= user_input_fetch_start_date:
        return 'Error: first fetch time delta should not be over one week.'
    if params.get('self_deployed'):
        if not params.get('auth_code') or not demisto.params().get('redirect_uri'):
            return 'Error: in the self_deployed authentication flow the authentication code parameter and ' \
                   'redirect uri cannot be empty.'
    return 'The basic parameters are ok, authentication cannot be checked using the test module. ' \
           'Please run ms-management-activity-list-subscriptions to test your credentials.'


def get_start_or_stop_subscription_human_readable(content_type, start_or_stop):
    if start_or_stop == 'start':
        human_readable = f'Successfully started subscription to content type: {content_type}'
    else:
        human_readable = f'Successfully stopped subscription to content type: {content_type}'
    return human_readable


def get_start_or_stop_subscription_context(content_type, start_or_stop):
    is_subscription_enabled = True if start_or_stop == 'start' else False
    subscription_context = {
        'ContentType': content_type,
        'Enabled': is_subscription_enabled
    }
    entry_context = {
        'MicrosoftManagement.Subscription(val.ContentType && val.ContentType === obj.ContentType)': subscription_context
    }
    return entry_context


def start_or_stop_subscription_command(client, args, start_or_stop):
    content_type = args.get('content_type')
    try:
        client.start_or_stop_subscription_request(content_type, start_or_stop)
        human_readable = get_start_or_stop_subscription_human_readable(content_type, start_or_stop)
        entry_context = get_start_or_stop_subscription_context(content_type, start_or_stop)

        return_outputs(
            readable_output=human_readable,
            outputs=entry_context,
            raw_response={}
        )

    except Exception as e:
        if start_or_stop == 'start' and 'The subscription is already enabled. No property change' in str(e):
            return_outputs('The subscription is already enabled.')
        else:
            raise


def get_enabled_subscriptions_content_types(enabled_subscriptions):
    enabled_subscriptions_content_types = [subscription.get('contentType') for subscription in enabled_subscriptions
                                           if subscription.get('status') == 'enabled']
    return enabled_subscriptions_content_types


def get_subscriptions_context(enabled_subscriptions):
    subscriptions_contexts = []
    for subscription_content_type in enabled_subscriptions:
        subscription_context = {
            'ContentType': subscription_content_type,
            'Enabled': True
        }
        subscriptions_contexts.append(subscription_context)
    return subscriptions_contexts


def list_subscriptions_command(client):
    subscriptions = client.list_subscriptions_request()
    enabled_subscriptions_content_types = get_enabled_subscriptions_content_types(
        subscriptions)  # Subscriptions are defined by their content type
    enabled_subscriptions_context = get_subscriptions_context(enabled_subscriptions_content_types)
    human_readable = tableToMarkdown('Current Subscriptions', enabled_subscriptions_content_types,
                                     headers='Current Subscriptions')
    entry_context = {
        'MicrosoftManagement.Subscription(val.ContentType && val.ContentType === obj.ContentType)': enabled_subscriptions_context
    }
    return_outputs(
        readable_output=human_readable,
        raw_response=enabled_subscriptions_context,
        outputs=entry_context
    )


def build_event_context(event_record):
    event_context = {
        'CreationTime': event_record.get('CreationTime'),
        'ID': event_record.get('Id'),
        'RecordType': event_record.get('RecordType'),
        'Operation': event_record.get('Operation'),
        'OrganizationID': event_record.get('OrganizationId'),
        'UserType': event_record.get('UserType'),
        'UserKey': event_record.get('UserKey'),
        'Workload': event_record.get('Workload'),
        'ResultsStatus': event_record.get('ResultStatus'),
        'ObjectID': event_record.get('ObjectId'),
        'UserID': event_record.get('UserId'),
        'ClientIP': event_record.get('ClientIP'),
        'Scope': event_record.get('Scope'),
    }

    # Remove keys with None value
    event_context = assign_params(**event_context)
    return event_context


def get_content_records_context(content_records):
    content_records_context = []
    for content_record in content_records:
        record_context = build_event_context(content_record)
        content_records_context.append(record_context)
    return content_records_context


def get_all_content_type_records(client, content_type, start_time, end_time, timeout=10):
    content_blobs = client.list_content_request(content_type, start_time, end_time, timeout)
    # The list_content request returns a list of content records, each containing a url that holds the actual data
    content_uris = [content_blob.get('contentUri') for content_blob in content_blobs]
    content_records: List = []
    for uri in content_uris:
        content_records_in_uri = client.get_blob_data_request(uri, timeout)
        content_records.extend(content_records_in_uri)
    return content_records


def create_events_human_readable(events_context, content_type):
    headers = ['ID', 'CreationTime', 'Workload', 'Operation']
    content_header = f'Content for content type {content_type}'
    human_readable = tableToMarkdown(content_header, events_context, headers=headers)
    return human_readable


def get_filter_accepted_values_list(filtered_field, filter_data):
    filter_accepted_values_string = filter_data.get(filtered_field)
    if filter_accepted_values_string:
        return filter_accepted_values_string.split(',')
    return None


def verify_record_type_is_legal(record_type):
    record_type_lowercase = record_type.lower()
    if record_type_lowercase not in CONTENT_TYPE_TO_TYPE_ID_MAPPING:
        return_error(f'Error: {record_type} is not a legal record type in the Microsoft Management Activity API.')


def record_types_to_type_ids(record_types_to_fetch):
    record_type_ids_to_fetch = []

    for record_type in record_types_to_fetch:
        verify_record_type_is_legal(record_type)
        # To lowercase to avoid user errors, such as 'quarantine' and 'Quarantine'
        record_type_lowercase = record_type.lower()
        record_type_id = CONTENT_TYPE_TO_TYPE_ID_MAPPING[record_type_lowercase]
        record_type_ids_to_fetch.append(record_type_id)
    return record_type_ids_to_fetch


def does_record_match_filters(record, filter_accepted_record_type_ids, filter_accepted_workloads,
                              filter_accepted_operations):
    should_filter_by_record_types = filter_accepted_record_type_ids is not None
    record_matches_record_type_filter = not should_filter_by_record_types or record.get('RecordType') in \
        filter_accepted_record_type_ids

    should_filter_by_workloads = filter_accepted_workloads is not None
    record_matches_workloads_filter = not should_filter_by_workloads or record.get('Workload') in \
        filter_accepted_workloads

    should_filter_by_operations = filter_accepted_operations is not None
    record_matches_operations_filter = not should_filter_by_operations or record.get('Operation') in \
        filter_accepted_operations

    return record_matches_record_type_filter and record_matches_workloads_filter and record_matches_operations_filter


def filter_records(content_records, filter_data):
    filter_accepted_workloads = get_filter_accepted_values_list('workloads_filter', filter_data)
    filter_accepted_operations = get_filter_accepted_values_list('operations_filter', filter_data)
    filter_accepted_record_types = get_filter_accepted_values_list('record_types_filter', filter_data)

    # User specifies the record types by type name, but the API returns the record types by ID.
    # Therefore we transform the names to IDs.
    filter_accepted_record_type_ids = record_types_to_type_ids(
        filter_accepted_record_types) if filter_accepted_record_types else None

    filtered_records = []
    for record in content_records:
        if does_record_match_filters(record, filter_accepted_record_type_ids, filter_accepted_workloads,
                                     filter_accepted_operations):
            filtered_records.append(record)
    return filtered_records


def list_content_command(client, args):
    content_type = args['content_type']
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    timeout = args.get('timeout', 10)

    content_records = get_all_content_type_records(client, content_type, start_time, end_time, timeout)
    filtered_content_records = filter_records(content_records, args)
    content_records_context = get_content_records_context(filtered_content_records)
    human_readable = create_events_human_readable(content_records_context, content_type)
    return_outputs(
        readable_output=human_readable,
        outputs={
            'MicrosoftManagement.ContentRecord(val.ID && val.ID === obj.ID)': content_records_context
        },
        raw_response=filtered_content_records
    )


def get_content_types_to_fetch(client):
    content_types_to_fetch = demisto.params().get('content_types_to_fetch')
    if not content_types_to_fetch:
        # Was not supplied by the user, so we will return all content types the user is subscribed to
        subscriptions = client.list_subscriptions_request()
        content_types_to_fetch = get_enabled_subscriptions_content_types(
            subscriptions)
    return content_types_to_fetch


def get_fetch_end_time_based_on_start_time(fetch_start_datetime):
    is_fetch_start_time_over_10_minutes_ago = (datetime.now() - timedelta(minutes=10) >= fetch_start_datetime)
    if is_fetch_start_time_over_10_minutes_ago:
        # Start and end time can't be over 24, so the fetch will end 24  hours after it's start.
        fetch_end_datetime = fetch_start_datetime + timedelta(minutes=10)
    else:
        fetch_end_datetime = datetime.now()
    return fetch_end_datetime


def get_fetch_start_and_end_time(last_run, first_fetch_datetime):
    if not last_run:
        fetch_start_datetime = first_fetch_datetime
    else:
        last_fetch = last_run.get('last_fetch')
        fetch_start_datetime = datetime.strptime(last_fetch, DATE_FORMAT)

    fetch_end_datetime = get_fetch_end_time_based_on_start_time(fetch_start_datetime)

    # The API expects strings of format YYYY:DD:MMTHH:MM:SS
    fetch_start_time_str = fetch_start_datetime.strftime(DATE_FORMAT)
    fetch_end_time_str = fetch_end_datetime.strftime(DATE_FORMAT)
    return fetch_start_time_str, fetch_end_time_str


def get_all_content_records_of_specified_types(client, content_types_to_fetch, start_time, end_time):
    all_content_records: List = list()
    content_types_to_fetch = content_types_to_fetch.split(',') if type(content_types_to_fetch) is str \
        else content_types_to_fetch
    for content_type in content_types_to_fetch:
        content_records_of_current_type = get_all_content_type_records(client, content_type, start_time, end_time)
        all_content_records.extend(content_records_of_current_type)
    return all_content_records


def content_records_to_incidents(content_records, start_time, end_time):
    incidents = []
    start_time_datetime = datetime.strptime(start_time, DATE_FORMAT)
    latest_creation_time_datetime = start_time_datetime

    record_ids_already_found: Set = set()

    for content_record in content_records:
        incident_creation_time_str = content_record['CreationTime']
        incident_creation_time_datetime = datetime.strptime(incident_creation_time_str, DATE_FORMAT)

        if incident_creation_time_datetime < start_time_datetime:
            pass
        incident_creation_time_in_incidents_format = incident_creation_time_str + 'Z'
        record_id = content_record['Id']
        incident = {
            'name': f'Microsoft Management Activity: {record_id}',
            'occurred': incident_creation_time_in_incidents_format,
            'rawJSON': json.dumps(content_record)
        }

        if incident['name'] in record_ids_already_found:
            pass
        else:
            record_ids_already_found.add(incident['name'])

        incidents.append(incident)
        if incident_creation_time_datetime > latest_creation_time_datetime:
            latest_creation_time_datetime = incident_creation_time_datetime

    latest_creation_time_str = datetime.strftime(latest_creation_time_datetime, DATE_FORMAT)

    if len(content_records) == 0 or latest_creation_time_str == start_time:
        latest_creation_time_str = end_time

    return incidents, latest_creation_time_str


def fetch_incidents(client, last_run, first_fetch_datetime):
    start_time, end_time = get_fetch_start_and_end_time(last_run, first_fetch_datetime)
    content_types_to_fetch = get_content_types_to_fetch(client)
    content_records = get_all_content_records_of_specified_types(client, content_types_to_fetch, start_time, end_time)
    filtered_content_records = filter_records(content_records, demisto.params())
    incidents, last_fetch = content_records_to_incidents(filtered_content_records, start_time, end_time)
    next_run = {'last_fetch': last_fetch}
    return next_run, incidents


def main():
    base_url = demisto.params().get('base_url', 'https://manage.office.com/api/v1.0/')
    verify_certificate = not demisto.params().get('insecure', False)

    first_fetch_delta = demisto.params().get('first_fetch_delta', '10 minutes').strip()
    first_fetch_datetime, _ = parse_date_range(first_fetch_delta)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            result = test_module()
            return_error(result)

        args = demisto.args()
        params = demisto.params()
        refresh_token = params.get('refresh_token', '')
        self_deployed = params.get('self_deployed', False)
        redirect_uri = params.get('redirect_uri', '')
        tenant_id = refresh_token if self_deployed else ''
        auth_id = params['auth_id']
        enc_key = params['enc_key']

        refresh_token = get_integration_context().get('current_refresh_token') or refresh_token

        client = Client(
            base_url=base_url,
            tenant_id=tenant_id,
            verify=verify_certificate,
            proxy=proxy,
            self_deployed=self_deployed,
            refresh_token=refresh_token,
            auth_and_token_url=auth_id,
            enc_key=enc_key,
            auth_code=params.get('auth_code', ''),
            redirect_uri=redirect_uri
        )

        access_token, token_data = client.get_access_token_data()
        client.access_token = access_token
        client.tenant_id = token_data['tid']

        if demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_datetime=first_fetch_datetime)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'ms-management-activity-start-subscription':
            start_or_stop_subscription_command(client, args, 'start')

        elif demisto.command() == 'ms-management-activity-stop-subscription':
            start_or_stop_subscription_command(client, args, 'stop')

        elif demisto.command() == 'ms-management-activity-list-subscriptions':
            list_subscriptions_command(client)

        elif demisto.command() == 'ms-management-activity-list-content':
            list_content_command(client, args)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


#== GENERATED CODE ==#
# This code was inserted in place of an API module.import traceback


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = '(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope; A scope to add to the headers. Else will get self.scope.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
