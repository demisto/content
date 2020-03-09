import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS

import json
import requests
import dateparser
import jwt

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'

class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url: str, username: str, password: str, verify: bool,
                 proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers = headers
        self.tenant_id = None
        self.suffix_template = "{}/activity/feed/subscriptions/{}"
        self.tenant_id_suffix = ''
        self.access_token = None

    @staticmethod
    def is_token_expired(integration_context):
        token_expiry_timestamp = int(integration_context["expires_on"])
        now_in_epoch = (datetime.now() - datetime(1970, 1, 1)).total_seconds()
        return token_expiry_timestamp <= now_in_epoch - 10  # Checking with a 10 seconds margin to be on the safe side

    @staticmethod
    def build_access_token_request_data(integration_context):
        redirect_uri = demisto.params().get('redirect_uri')
        auth_code = demisto.params().get('auth_code')
        client_id = demisto.params().get('client_id')
        client_secret = demisto.params().get('client_secret')
        data = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'client_secret': client_secret,
            'resource': 'https://manage.office.com'
        }

        if not integration_context:
            data['code'] = auth_code
            data['grant_type'] = 'authorization_code'
        else:
            data['refresh_token'] = integration_context['refresh_token']
            data['grant_type'] = 'refresh_token'

        return data

    @staticmethod
    def create_new_integration_context(get_access_token_response):
        new_integration_context = {
            'refresh_token': get_access_token_response.get('refresh_token'),
            'access_token': get_access_token_response.get('access_token'),
            'expires_on': get_access_token_response.get('expires_on')
        }
        return new_integration_context

    def get_access_token_request(self):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        integration_context = demisto.getIntegrationContext()
        if integration_context and not Client.is_token_expired(integration_context):
            return integration_context

        data = Client.build_access_token_request_data(integration_context)

        response = self._http_request(
            method='POST',
            url_suffix='',
            full_url='https://login.windows.net/common/oauth2/token',
            headers=headers,
            json_data=data
        )

        new_integration_context = Client.create_new_integration_context(response)
        demisto.setIntegrationContext(new_integration_context)
        return response

    def get_access_token_data(self):
        refresh_token_response = self.get_access_token_request()
        access_token_jwt = refresh_token_response.get('access_token')
        token_data = jwt.decode(access_token_jwt, verify=False)
        return access_token_jwt, token_data

    def get_blob_data_request(self, blob_url):
        auth_string = 'Bearer {}'.format(self.access_token)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': auth_string
        }
        response = self._http_request(
            method='GET',
            url_suffix='',
            full_url=blob_url,
            headers=headers
        )
        return response

    def list_content_request(self, content_type, start_time, end_time):
        auth_string = 'Bearer {}'.format(self.access_token)
        headers = {
            'Authorization': auth_string
        }
        params = {
            'contentType': content_type
        }

        if start_time and end_time:
            params['startTime'] = start_time
            params['endTime'] = end_time

        response = self._http_request(
            method='GET',
            url_suffix=self.suffix_template.format(self.tenant_id, 'content'),
            headers=headers,
            params=params
        )
        return response

    def list_subscriptions_request(self):
        auth_string = 'Bearer {}'.format(self.access_token)
        headers = {
            'Authorization': auth_string
        }
        response = self._http_request(
            method='GET',
            url_suffix=self.suffix_template.format(self.tenant_id, 'list'),
            headers=headers
        )
        return response

    def start_or_stop_subscription_request(self, content_type, start_or_stop_suffix):
        auth_string = 'Bearer {}'.format(self.access_token)
        headers = {
            'Authorization': auth_string
        }
        params = {
            'contentType': content_type
        }
        response = self._http_request(
            method='POST',
            url_suffix=self.suffix_template.format(self.tenant_id, start_or_stop_suffix),
            headers=headers,
            params=params
        )
        return response


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    fetch_delta = demisto.params().get("first_fetch_delta", "1440")
    if not fetch_delta.isdigit():
        return "Error: first fetch start must be a positive integer."
    fetch_delta = int(fetch_delta)
    if fetch_delta > 1440:
        return "Error: first fetch start cannot be more than 1440 minutes."
    access_token, token_data = client.get_access_token_data()
    if not access_token:
        return "Error: unable to get perform successful authentication. Please re-submit parameters values."
    return 'ok'


def start_or_stop_subscription_command(client, args, start_or_stop):
    content_type = args.get('content_type')
    res = client.start_or_stop_subscription_request(content_type, start_or_stop)
    if start_or_stop == 'start':
        human_readable = "Successfully started subscription to content type: {}".format(content_type)
    else:
        human_readable = "Successfully stopped subscription to content type: {}".format(content_type)

    return_outputs(
        readable_output=human_readable,
        outputs={},
        raw_response=res
    )


def get_all_subscribed_content_types(client):
    subscriptions_data = client.list_subscriptions_request()
    # Since subscriptions are defined by there content type, we need the content types of enabled subscriptions
    enabled_subscriptions = [subscription.get('contentType') for subscription in subscriptions_data
                             if subscription.get('status') == 'enabled']
    return enabled_subscriptions


def list_subscriptions_command(client):
    # Since subscriptions are defined by there content type, we need the content types of enabled subscriptions
    enabled_subscriptions = get_all_subscribed_content_types(client)
    human_readable = tableToMarkdown('Current Subscriptions', enabled_subscriptions, headers='Current Subscriptions')

    entry_context = {
        'MicrosoftManagement.Subscription(val && val == obj)': enabled_subscriptions
    }
    return_outputs(
        readable_output=human_readable,
        raw_response=enabled_subscriptions,
        outputs=entry_context
    )


def build_event_context(event_record):
    event_context = {
        "CreationTime": event_record.get("Creation Time"),
        "ID": event_record.get("Id"),
        "RecordType": event_record.get("RecordType"),
        "Operation": event_record.get("Operation"),
        "OrganizationID": event_record.get("OrganizationId"),
        "UserType": event_record.get("UserType"),
        "UserKey": event_record.get("UserKey"),
        "Workload": event_record.get("Workload"),
        "ResultsStatus": event_record.get("ResultStatus"),
        "ObjectID": event_record.get("ObjectId"),
        "UserID": event_record.get("UserId"),
        "ClientIP": event_record.get("ClientIP"),
        "Scope": event_record.get("Scope"),
    }
    # Remove keys with None value
    for key in event_context:
        if not event_context[key]:
            del event_context[key]
    return event_context


def get_content_records_context(content_records):
    content_records_context = []
    for content_record in content_records:
        record_context = build_event_context(content_record)
        content_records_context.append(record_context)
    return content_records_context


def get_all_content_type_records(client, content_type, start_time, end_time):
    # The request returns a list of content records, each containing a url that holds the actual data
    content_blobs = client.list_content_request(content_type, start_time, end_time)
    content_uris = [content_blob.get("contentUri") for content_blob in content_blobs]
    content_records = []
    for uri in content_uris:
        content_records_in_uri = client.get_blob_data_request(uri)
        content_records.extend(content_records_in_uri)
    return content_records


def create_events_human_readable(events_context, content_type):
    headers = ["ID", "Creation Time", "Workload", "Operation"]
    content_header = "Content for content type {}".format(content_type)
    human_readable = tableToMarkdown(content_header, events_context, headers=headers)
    return human_readable


def list_content_command(client, args):

    content_type = args['content_type']
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    if (start_time and not end_time) or (end_time and not start_time):
        return_error("Error: Start time and end time must both be specified (or both omitted).")

    content_records = get_all_content_type_records(client, content_type, start_time, end_time)
    content_records_context = get_content_records_context(content_records)
    human_readable = create_events_human_readable(content_records_context, content_type)
    return_outputs(
        readable_output=human_readable,
        outputs={
            "MicrosoftManagement.ContentRecord(val.ID && val.ID === obj.ID)": content_records_context
        },
        raw_response=content_records
    )


def get_content_types_to_fetch(client):
    content_types_to_fetch = demisto.params().get("content_types_to_fetch")
    if not content_types_to_fetch:
        # Was not supplied by the user, so we will return all content types the user is subscribed to
        content_types_to_fetch = get_all_subscribed_content_types(client)
    return content_types_to_fetch


def get_fetch_start_and_end_time(last_run, first_fetch_delta_in_minutes):
    if not last_run:
        fetch_start_datetime = datetime.now() - timedelta(minutes=first_fetch_delta_in_minutes)
        if first_fetch_delta_in_minutes > 1440:
            fetch_delta_minus_one_day = first_fetch_delta_in_minutes - 1440
            fetch_end_datetime = datetime.now() - timedelta(minutes=fetch_delta_minus_one_day)
        else:
            fetch_end_datetime = datetime.now()

    else:
        last_fetch = last_run.get('last_fetch')
        fetch_start_datetime = datetime.strptime(last_fetch, DATE_FORMAT)
        fetch_start_to_now_delta = datetime.now() - fetch_start_datetime
        days_since_fetch_start = fetch_start_to_now_delta.days
        if days_since_fetch_start > 0:
            fetch_end_datetime = fetch_start_datetime + timedelta(days=1)
        else:
            fetch_end_datetime = datetime.now()

    # The API expects strings of format YYYY:DD:MMTHH:MM:SS
    fetch_start_time_str = fetch_start_datetime.strftime(DATE_FORMAT)
    fetch_end_time_str = fetch_end_datetime.strftime(DATE_FORMAT)
    return fetch_start_time_str, fetch_end_time_str


def get_all_content_records_of_specified_types(client, content_types_to_fetch, start_time, end_time):
    all_content_records = []
    content_types_to_fetch = content_types_to_fetch.split(',') if type(content_types_to_fetch) is str else content_types_to_fetch
    for content_type in content_types_to_fetch:
        content_records_of_current_type = get_all_content_type_records(client, content_type, start_time, end_time)
        all_content_records.extend(content_records_of_current_type)
    return all_content_records


def content_records_to_incidents(content_records, start_time, end_time):
    incidents = []
    start_time_datetime = datetime.strptime(start_time, DATE_FORMAT)
    latest_creation_time_datetime = start_time_datetime

    record_ids_already_found = set()

    for content_record in content_records:
        incident_creation_time_str = content_record['CreationTime']
        incident_creation_time_datetime = datetime.strptime(incident_creation_time_str, DATE_FORMAT)

        if incident_creation_time_datetime < start_time_datetime:
            pass
        incident = {
            'name': content_record['Id'],
            'occurred': incident_creation_time_str,
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


def fetch_incidents(client, last_run, first_fetch_delta):
    start_time, end_time = get_fetch_start_and_end_time(last_run, first_fetch_delta)
    content_types_to_fetch = get_content_types_to_fetch(client)
    content_records = get_all_content_records_of_specified_types(client, content_types_to_fetch, start_time, end_time)
    incidents, last_fetch = content_records_to_incidents(content_records, start_time, end_time)
    next_run = {'last_fetch': last_fetch}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    base_url = 'https://manage.office.com/api/v1.0/'
    verify_certificate = not demisto.params().get('insecure', False)

    first_fetch_delta = demisto.params().get('first_fetch_delta', '1440').strip()
    first_fetch_delta = int(first_fetch_delta)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        args = demisto.args()
        client = Client(
            base_url, username='', password='',
            verify=verify_certificate,
            proxy=proxy, headers='')

        access_token, token_data = client.get_access_token_data()
        client.access_token = access_token
        client.tenant_id = token_data["tid"]

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_delta=first_fetch_delta)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'ms-management-start-subscription':
            start_or_stop_subscription_command(client, args, "start")

        elif demisto.command() == 'ms-management-stop-subscription':
            start_or_stop_subscription_command(client, args, "stop")

        elif demisto.command() == 'ms-management-list-subscriptions':
            list_subscriptions_command(client)

        elif demisto.command() == 'ms-management-list-content':
            list_content_command(client, args)


    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
