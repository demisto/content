# IMPORTS
from email.mime.text import MIMEText
from smtplib import SMTP

import demistomock as demisto
from CommonServerPython import *

import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''


INCOMING_MAPPER = 'User Profile - Okta (Incoming)'
OUTGOING_MAPPER = 'User Profile - Okta (Outgoing)'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SEARCH_LIMIT = 1000

DEPROVISIONED_STATUS = 'DEPROVISIONED'
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"


'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify=True, proxy=False, headers=None, auth=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers
        self.auth = auth
        self.iam = IAMCommandHelper()

    def http_request(self, method, url_suffix, full_url=None, params=None, data=None, headers=None):
        if headers is None:
            headers = self.headers
        full_url = full_url if full_url else urljoin(self.base_url, url_suffix)
        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            headers=headers,
            params=params,
            json=data
        )
        return res

    # Getting User Id with a given username
    def get_user_id(self, username):
        uri = 'users'
        query_params = {
            'filter': encode_string_results(f'profile.login eq "{username}"')
        }

        res = self.http_request(
            method='GET',
            url_suffix=uri,
            params=query_params

        )
        return res

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/deactivate'
        return self.http_request(
            method="POST",
            url_suffix=uri
        )

    def activate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/activate'
        return self.http_request(
            method="POST",
            url_suffix=uri
        )

    def get_user(self, user_term):
        uri = f'users/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def create_user(self, profile):
        body = {
            'profile': profile,
            'groupIds': [],
            'credentials': {}
        }
        uri = 'users'
        query_params = {
            'activate': 'true',
            'provider': 'true'
        }
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=body,
            params=query_params
        )

    def update_user(self, user_id, profile):
        body = {
            "profile": profile,
            "credentials": {}
        }
        uri = f"users/{user_id}"
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=body
        )

    def get_assigned_user_for_app(self, application_id, user_id):
        uri = f"/apps/{application_id}/users/{user_id}"
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def get_logs(self, filter, from_date, to_date):
        uri = 'logs'
        query_params = {}
        query_params['since'] = encode_string_results(from_date)
        query_params['until'] = encode_string_results(to_date)
        query_params['filter'] = encode_string_results(filter)

        return self.get_paged_results(uri, query_params)

    def get_paged_results(self, uri, query_param=None):
        response = self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_param
        )
        paged_results = response.json()

        if response.status_code != 200:
            raise Exception(f'Error occurred while calling Okta API. Response: {response.json()}')
        while "next" in response.links and len(response.json()) > 0:
            next_page = response.links.get("next").get("url")
            response = self.http_request(
                method="GET",
                full_url=next_page,
                url_suffix='',
                params=query_param

            )
            if response.status_code != 200:
                raise Exception(f'Error occurred while calling Okta API. Response: {response.json()}')
            paged_results += response.json()
        return paged_results


'''HELPER FUNCTIONS'''


def get_time_elapsed(fetch_time, last_run):
    now = datetime.now()
    demisto.info("Okta Last Run: " + str(last_run))
    if 'time' in last_run:
        # Get Last run and parse to date format. Workday report will be pulled from last run time to current time
        last_run_time = last_run['time']
        # Convert to date format
        last_run = datetime.strptime(last_run_time, DATE_FORMAT)
        time_elapsed_in_minutes = (now - last_run).total_seconds() / 60
    else:
        # If last run time is not set, data will be pulled using fetch_time
        # i.e. last 10min if fetch events is set to 10min
        last_run_time = (now - timedelta(minutes=int(fetch_time))).strftime(
            DATE_FORMAT)
        time_elapsed_in_minutes = fetch_time

    return time_elapsed_in_minutes, last_run_time


def send_email(subject, body=''):
    params = demisto.params()
    smtp_server_host = params.get('smtp_server')
    smtp_server_port = params.get('smtp_port')
    from_email = params.get('from_email')
    to_email = params.get('email_notification_ids')

    # Send email if smtp details are configured
    if smtp_server_host and smtp_server_port and from_email and to_email:
        smtp_client = SMTP(smtp_server_host, int(smtp_server_port), local_hostname=smtp_server_host)
        smtp_client.ehlo()
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        smtp_client.sendmail(from_email, to_email.split(','), msg.as_string())
        smtp_client.quit()


def get_error_details(res_json):
    error_msg = f'{res_json.get("errorSummary")}. '
    causes = ''
    for idx, cause in enumerate(res_json.get('errorCauses'), 1):
        causes += f'{idx}. {cause.get("errorSummary")}\n'
    if causes:
        error_msg += f'Reason:\n{causes}'
    return error_msg


'''COMMAND FUNCTIONS'''


def test_module(client, args):
    # Validating fetch_time parameter
    fetch_time = demisto.params().get('fetch_events_time_minutes')
    is_fetch = demisto.params().get('isFetch')
    try:
        if fetch_time not in [None, ''] and is_fetch:
            fetch_time = int(fetch_time)
    except Exception:
        raise Exception('Please enter valid fetch_time parameter.')

    uri = 'users/me'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200:
        return 'ok', None, None
    else:
        raise Exception(f'Failed: Error Code: {res.status_code}. Error Response: {res.json()}')


def enable_disable_user_command(client, args):
    user_profile = args.get('user-profile')
    app_data = client.iam.map_user_profile_to_app_data(user_profile, OUTGOING_MAPPER)
    user_id = app_data.pop('id')

    if demisto.command() == 'enable-user':
        res = client.activate_user(user_id)
        active = True
    else:
        res = client.deactivate_user(user_id)
        active = False

    res_json = res.json()

    if res.status_code == 200:
        return client.iam.return_outputs(success=True,
                                         iden=res_json.get('id'),
                                         email=res_json.get('profile', {}).get('email'),
                                         username=res_json.get('profile', {}).get('login'),
                                         details=res_json,
                                         active=active)

    return client.iam.return_outputs(success=False,
                                     error_code=res_json.get('errorCode'),
                                     error_message=get_error_details(res_json),
                                     details=res_json)


def create_user_command(client, args):
    user_profile = args.get('user-profile')
    app_data = client.iam.map_user_profile_to_app_data(user_profile, OUTGOING_MAPPER)
    res = client.create_user(app_data)
    res_json = res.json()

    if res.status_code == 200:
        active = False if res_json.get('status') == DEPROVISIONED_STATUS else True

        return client.iam.return_outputs(success=True,
                                         iden=res_json.get('id'),
                                         email=res_json.get('profile', {}).get('email'),
                                         username=res_json.get('profile', {}).get('login'),
                                         details=res_json,
                                         active=active)

    return client.iam.return_outputs(success=False,
                                     error_code=res_json.get('errorCode'),
                                     error_message=get_error_details(res_json),
                                     details=res_json)


def get_user_command(client, args):
    user_profile = args.get('user-profile')
    app_data = client.iam.map_user_profile_to_app_data(user_profile, OUTGOING_MAPPER)
    user_id = app_data.get('id')
    res = client.get_user(user_id)
    res_json = res.json()

    if res.status_code == 200:
        active = False if res_json.get('status') == DEPROVISIONED_STATUS else True

        return client.iam.return_outputs(success=True,
                                         iden=res_json.get('id'),
                                         email=res_json.get('profile', {}).get('email'),
                                         username=res_json.get('profile', {}).get('login'),
                                         details=res_json,
                                         active=active)

    return client.iam.return_outputs(success=False,
                                     error_code=res_json.get('errorCode'),
                                     error_message=get_error_details(res_json),
                                     details=res_json)


def update_user_command(client, args):
    user_profile = args.get('user-profile')
    app_data = client.iam.map_user_profile_to_app_data(user_profile, OUTGOING_MAPPER)
    if 'id' not in app_data and args.get('create-if-not-exists'):
        return create_user_command(client, args)
    user_id = app_data.pop('id')
    res = client.update_user(user_id, app_data)
    res_json = res.json()

    if res.status_code == 200:
        active = False if res_json.get('status') == DEPROVISIONED_STATUS else True

        return client.iam.return_outputs(success=True,
                                         iden=res_json.get('id'),
                                         email=res_json.get('profile', {}).get('email'),
                                         username=res_json.get('profile', {}).get('login'),
                                         details=res_json,
                                         active=active)

    return client.iam.return_outputs(success=False,
                                     error_code=res_json.get('errorCode'),
                                     error_message=get_error_details(res_json),
                                     details=res_json)


def fetch_incidents(client, last_run, fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: Okta client
        last_run: The greatest incident created_time we fetched from last fetch
        fetch_time: The time interval when the function should execute and return events/incidents

    Returns:
        last_run: This will be last_run in the next fetch-incidents
        events: Incidents/Events that will be created in Cortex XSOAR
    """
    events = []

    try:
        # If there is no fetch time configured, it will be set to 0 and no events will be pulled
        fetch_time = int(fetch_time) if fetch_time else 0
        time_elapsed_in_minutes, last_run_time = get_time_elapsed(fetch_time, last_run)
        filter = demisto.params().get('fetchLogsQuery')

        if fetch_time != 0 and time_elapsed_in_minutes >= fetch_time and filter:
            from_date_time = last_run_time
            to_date_time = datetime.now().strftime(DATE_FORMAT)
            demisto.info(f"Okta: Fetching logs from {from_date_time} to {to_date_time}")
            log_events = client.get_logs(filter, from_date_time, to_date_time)
            for entry in log_events:
                # Set the Raw JSON to the event. Mapping will be done at the classification and mapping
                event = {"rawJSON": json.dumps(entry)}
                events.append(event)
            last_run_time = datetime.now().strftime(DATE_FORMAT)

        last_run = {'time': last_run_time}
    except Exception as e:
        demisto.error(f'Failed to fetch Okta log events. From Date = {from_date_time}. To Date = {to_date_time}')
        send_email("ERROR: Okta Fetch Events Failed", traceback.format_exc())
        raise e

    return last_run, events


def get_assigned_user_for_app_command(client, args):
    user_id = args.get('userId')
    application_id = args.get('applicationId')
    output_data = {}

    res = client.get_assigned_user_for_app(application_id=application_id, user_id=user_id)
    res_json = res.json()
    if res.status_code == 200:
        output_data['success'] = True
        for k, v in res_json.items():
            output_data[k] = v
    elif res.status_code == 404:
        output_data['success'] = False
        output_data['errorCode'] = res.status_code
        output_data['errorMessage'] = res_json.get('errorSummary')
    else:
        output_data['success'] = False
        output_data['errorCode'] = res_json.get('errorCode')
        output_data['errorMessage'] = res_json.get('errorSummary')

    readable_output = tableToMarkdown(name="Okta User App Assignment:",
                                      t=output_data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    outputs = {
        'Okta.UserAppAssignment(val.ID && val.ID === obj.ID)': output_data
    }
    return (
        readable_output,
        outputs,
        output_data
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    base_url = urljoin(demisto.params()['url'].strip('/'), '/api/v1/')
    apitoken = demisto.params().get('apitoken')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    LOG(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'disable-user': enable_disable_user_command,
        'enable-user': enable_disable_user_command,
        'okta-get-assigned-user-for-app': get_assigned_user_for_app_command
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {apitoken}'
        },
        proxy=proxy)

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        if command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            last_run, events = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                fetch_time=params.get('fetch_events_time_minutes'))

            demisto.setLastRun(last_run)
            demisto.incidents(events)
    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
