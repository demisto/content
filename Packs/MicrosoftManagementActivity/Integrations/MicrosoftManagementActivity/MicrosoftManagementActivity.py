import demistomock as demisto
from CommonServerPython import *
import jwt
import json
import requests
from typing import Set, List

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
                 enc_key, auth_code, tenant_id):
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
                                         token_retrieval_url='https://login.windows.net/common/oauth2/token')

    def get_access_token_data(self):
        access_token_jwt = self.ms_client.get_access_token()
        token_data = jwt.decode(access_token_jwt, verify=False)
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
    if params.get('self_deployed') and not params.get('auth_code'):
        return 'Error: in the self_deployed authentication flow the authentication code parameter cannot be empty.'
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
        tenant_id = refresh_token if self_deployed else ''
        auth_id = params['auth_id']
        enc_key = params['enc_key']

        refresh_token = (demisto.getIntegrationContext().get('current_refresh_token') or refresh_token)

        client = Client(
            base_url=base_url,
            tenant_id=tenant_id,
            verify=verify_certificate,
            proxy=proxy,
            self_deployed=self_deployed,
            refresh_token=refresh_token,
            auth_and_token_url=auth_id,
            enc_key=enc_key,
            auth_code=params.get('auth_code', '')
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


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
