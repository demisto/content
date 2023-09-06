import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import urllib.parse
from typing import Dict
from enum import Enum
from string import Template
import bz2
import base64
import math


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
MAX_ATTEMPTS = 3
BASE_URL = 'https://api.dlp.paloaltonetworks.com/v1/'
PAN_AUTH_URL = 'https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token'
REPORT_URL = 'public/report/{}'
INCIDENTS_URL = 'public/incident-notifications'
REFRESH_TOKEN_URL = 'public/oauth/refreshToken'
UPDATE_INCIDENT_URL = 'public/incident-feedback'
SLEEP_TIME_URL = 'public/seconds-between-incident-notifications-pull'
FETCH_SLEEP = 5  # sleep between fetches (in seconds)
LAST_FETCH_TIME = 'last_fetch_time'
DEFAULT_FIRST_FETCH = '60 minutes'
ACCESS_TOKEN = 'access_token'
RESET_KEY = 'reset'
CREDENTIAL = 'credential'
IDENTIFIER = 'identifier'
PASSWORD = 'password'


class FeedbackStatus(Enum):
    PENDING_RESPONSE = 'PENDING_RESPONSE'
    CONFIRMED_SENSITIVE = 'CONFIRMED_SENSITIVE'
    CONFIRMED_FALSE_POSITIVE = 'CONFIRMED_FALSE_POSITIVE'
    EXCEPTION_REQUESTED = 'EXCEPTION_REQUESTED'
    OPERATIONAL_ERROR = 'OPERATIONAL_ERROR'
    EXCEPTION_GRANTED = 'EXCEPTION_GRANTED'
    EXCEPTION_NOT_REQUESTED = 'EXCEPTION_NOT_REQUESTED'
    SEND_NOTIFICATION_FAILURE = 'SEND_NOTIFICATION_FAILURE'
    EXCEPTION_DENIED = 'EXCEPTION_DENIED'


class Client(BaseClient):

    def __init__(self, url, credentials, insecure, proxy):
        super().__init__(base_url=url, headers=None, verify=not insecure, proxy=proxy)
        self.credentials = credentials
        credential_name = credentials[CREDENTIAL]
        if not credential_name:
            self.access_token = credentials[IDENTIFIER]
            self.refresh_token = credentials[PASSWORD]
        else:
            self.access_token = ''

    def _refresh_token(self):
        """Refreshes Access Token"""
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json"
        }
        params = {
            "refresh_token": self.refresh_token
        }
        print_debug_msg(f'Calling endpoint {self._base_url}{REFRESH_TOKEN_URL}')
        try:
            r = self._http_request(
                method='POST',
                headers=headers,
                url_suffix=REFRESH_TOKEN_URL,
                json_data=params,
                ok_codes=[200, 201, 204]
            )
            new_token = r.get('access_token')
            if new_token:
                self.access_token = new_token

        except Exception as e:
            print_debug_msg(str(e))
            raise

    def _refresh_token_with_client_credentials(self):
        client_id = self.credentials[IDENTIFIER]
        client_secret = self.credentials[PASSWORD]
        credentials = f'{client_id}:{client_secret}'
        auth_header = f'Basic {b64_encode(credentials)}'
        headers = {
            'Authorization': auth_header,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = 'grant_type=client_credentials'
        try:
            r = self._http_request(
                full_url=PAN_AUTH_URL,
                method='POST',
                headers=headers,
                data=payload,
                ok_codes=[200, 201, 204]
            )
            new_token = r.get('access_token')
            if new_token:
                self.access_token = new_token

        except Exception as e:
            print_debug_msg(str(e))
            raise

    def _handle_403_errors(self, res):
        """
        Handles 403 exception on get-dlp-report and tries to refresh token
        Args:
            res: Response of DLP API call
        """
        if res.status_code != 403:
            return
        try:
            print_debug_msg("Got 403, attempting to refresh access token")
            if self.credentials[CREDENTIAL]:
                print_debug_msg("Requesting access token with client id/client secret")
                self._refresh_token_with_client_credentials()
            else:
                print_debug_msg("Requesting new access token with old access token/refresh token")
                self._refresh_token()
        except Exception:
            pass

    def _get_dlp_api_call(self, url_suffix: str):
        """
        Makes a HTTPS Get call on the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
        """
        count = 0
        print_debug_msg(f'Calling GET method on {self._base_url}{url_suffix}')
        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method='GET',
                headers={'Authorization': "Bearer " + self.access_token},
                url_suffix=url_suffix,
                ok_codes=[200, 201, 204],
                error_handler=self._handle_403_errors,
                resp_type='',
                return_empty_response=True
            )
            if res.status_code != 403:
                break
            count += 1

        result_json = {}
        if res.status_code != 204:
            try:
                result_json = res.json()
            # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError
            except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError):
                result_json = {}

        return result_json, res.status_code

    def _post_dlp_api_call(self, url_suffix: str, payload: Dict = None):
        """
        Makes a POST HTTP(s) call to the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
            payload: Optional JSON payload
        """
        count = 0

        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method='POST',
                headers={'Authorization': f"Bearer {self.access_token}"},
                url_suffix=url_suffix,
                json_data=payload,
                ok_codes=[200, 201, 204],
                error_handler=self._handle_403_errors,
                resp_type='response',
                return_empty_response=True
            )
            if res.status_code != 403:
                break
            count += 1

        result_json = {}
        if res.status_code != 204:
            try:
                result_json = res.json()
            # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError
            except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError):
                result_json = {}

        return result_json, res.status_code

    def set_access_token(self, access_token):
        self.access_token = access_token

    def get_dlp_report(self, report_id: str, fetch_snippets=False):
        """
        Fetches DLP reports
        Args:
            report_id: Report ID to fetch from DLP service
            fetch_snippets: if True, fetches the snippets

        Returns: DLP Report json
        """
        url = REPORT_URL.format(report_id)
        if fetch_snippets:
            url = url + "?fetchSnippets=true"

        return self._get_dlp_api_call(url)

    def get_dlp_incidents(self, regions: str, start_time: int = None, end_time: int = None) -> dict:
        url = INCIDENTS_URL
        params = {}
        if regions:
            params['regions'] = regions
        if start_time:
            params['start_timestamp'] = str(start_time)
        if end_time:
            params['end_timestamp'] = str(end_time)
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"
        resp, status_code = self._get_dlp_api_call(url)
        return resp

    def update_dlp_incident(self, incident_id: str, feedback: FeedbackStatus, user_id: str, region: str,
                            report_id: str, dlp_channel: str, error_details: str = None):
        """
                Update Incident with user provided feedback
                Args:
                    incident_id: The id of the incident to update
                    feedback: 'business_justified', 'true_positive' or 'false_positive'
                    user_id: The user that initiated the request
                    region: The DLP region
                    report_id: The report ID for the incident
                    dlp_channel: The DLP channel (service name)
                    error_details: The error details if there is an error

                Returns: DLP Incident json
                """
        payload = {
            'user_id': user_id,
            'report_id': report_id,
            'service_name': dlp_channel
        }
        if error_details:
            payload['error_details'] = error_details

        url = f'{UPDATE_INCIDENT_URL}/{incident_id}?feedback_type={feedback.value}&region={region}'
        return self._post_dlp_api_call(url, payload)

    def query_for_sleep_time(self):
        resp, status = self._get_dlp_api_call(SLEEP_TIME_URL)
        return resp


def parse_data_pattern_rule(report_json, verdict_field, results_field):
    """
    Parses data pattern matches from a given rule in DLP report JSON
    Args:
        report_json: DLP report json
        verdict_field: Name of the verdict field
        results_field: Name of the result field

    Returns: data pattern matches for the given rule

    """
    if report_json.get(verdict_field) != "MATCHED":
        return []
    data_patterns = []
    for dp in report_json.get("scanContentRawReport", {}).get(results_field, []):
        if (dp.get("state") == "EVALUATED") and (dp.get("unique_detection_frequency", 0) >= 1):
            data_patterns.append({
                'DataPatternName': dp.get('name'),
                'LowConfidenceFrequency': dp.get('low_confidence_frequency'),
                'HighConfidenceFrequency': dp.get('high_confidence_frequency'),
                'MediumConfidenceFrequency': dp.get('medium_confidence_frequency'),
                'Detections': dp.get("detections")
            })
    return data_patterns


def parse_data_patterns(report_json):
    """
    Parse data pattern matches from the raw report
    Args:
        report_json: DLP report JSON

    Returns: Data pattern matches
    """
    data_patterns = []
    data_patterns.extend(
        parse_data_pattern_rule(report_json, "data_pattern_rule_1_verdict", "data_pattern_rule_1_results"))
    data_patterns.extend(
        parse_data_pattern_rule(report_json, "data_pattern_rule_2_verdict", "data_pattern_rule_2_results"))
    return {
        'DataProfile': report_json.get("data_profile_name"),
        'DataPatternMatches': data_patterns
    }


def convert_to_human_readable(data_patterns):
    """
    Converts the results for human readable format
    Args:
        data_patterns: Data Pattern matches

    Returns: Human Readable Format result
    """
    matches: list = []
    if not data_patterns:
        return matches
    headers = ['DataPatternName', 'ConfidenceFrequency']
    for k in data_patterns.get("DataPatternMatches", []):
        match = {
            'DataPatternName': k.get('DataPatternName'),
            'ConfidenceFrequency': {
                'Low': k.get('LowConfidenceFrequency'),
                'Medium': k.get('MediumConfidenceFrequency'),
                'High': k.get('HighConfidenceFrequency')
            }
        }
        index = 1
        detections = k.get('Detections', [])
        if detections:
            for detection in detections:
                col = 'Detection {}'.format(index)
                if col not in headers:
                    headers.append(col)
                match[col] = detection
                index += 1
        matches.append(match)
    title = 'DLP Report for profile: {}'.format(data_patterns.get("DataProfile"))
    return tableToMarkdown(title, matches, headers)


def parse_dlp_report(report_json) -> CommandResults:
    """
    Parses DLP Report for display
    Args:
        report_json: DLP report json

    Returns: DLP report results
    """
    data_patterns = parse_data_patterns(report_json)
    return CommandResults(
        outputs_prefix='DLP.Report',
        outputs_key_field='DataPatternName',
        outputs=data_patterns,
        readable_output=convert_to_human_readable(data_patterns),
        raw_response=report_json
    )


def test(client):
    """ Test Function to test validity of access and refresh tokens"""
    report_json, status_code = client.get_dlp_report('1')
    if status_code in [200, 204]:
        return_results("ok")
    else:
        raise DemistoException("Integration test failed: Unexpected status ({})".format(status_code))


def print_debug_msg(msg: str):
    """
    Prints a message to debug with QRadarMsg prefix.
    Args:
        msg (str): Message to be logged.

    """
    demisto.debug(f'PAN-DLP-Msg - {msg}')


def update_incident_command(client: Client, args: dict) -> CommandResults:
    incident_id = args.get('incident_id', '')
    feedback = args.get('feedback', '')
    user_id = args.get('user_id', '')
    region = args.get('region', '')
    report_id = args.get('report_id', '')
    dlp_channel = args.get('dlp_channel', '')
    error_details = args.get('error_details')
    feedback_enum = FeedbackStatus[feedback.upper()]
    result_json, status = client.update_dlp_incident(incident_id, feedback_enum, user_id, region, report_id,
                                                     dlp_channel, error_details)

    output = {
        'feedback': feedback_enum.value,
        'success': status == 200
    }
    if feedback_enum == FeedbackStatus.EXCEPTION_GRANTED:
        minutes = result_json['expiration_duration_in_minutes']
        if minutes and minutes < 60:
            output['duration'] = f'{minutes} minutes'
        elif minutes:
            output['duration'] = f'{minutes / 60} hours'

        result = CommandResults(
            outputs_prefix="Exemption",
            outputs_key_field='duration',
            outputs=output)
    else:
        result = CommandResults(
            outputs_prefix="IncidentUpdate",
            outputs_key_field='feedback',
            outputs=output)
    return result


def parse_incident_details(compressed_details: str):
    details_byte_data = bz2.decompress(base64.b64decode(compressed_details))
    details_string = details_byte_data.decode('utf-8')
    details_obj = json.loads(details_string)
    return details_obj


def create_incident(notification: dict, region: str):
    raw_incident = notification['incident']
    previous_notifications = notification['previous_notifications']
    raw_incident['region'] = region
    raw_incident['previousNotification'] = previous_notifications[0] if len(previous_notifications) > 0 else None
    incident_creation_time = dateparser.parse(raw_incident['createdAt'])
    parsed_details = parse_incident_details(raw_incident['incidentDetails'])
    raw_incident['incidentDetails'] = parsed_details
    if not raw_incident['userId']:
        for header in parsed_details['headers']:
            if header['attribute_name'] == 'username':
                raw_incident['userId'] = header['attribute_value']

    event_dump = json.dumps(raw_incident)
    incident = {
        'name': f'Palo Alto Networks DLP Incident {raw_incident["incidentId"]}',
        'type': 'Data Loss Prevention',
        'occurred': incident_creation_time.isoformat(),  # type: ignore
        'rawJSON': event_dump,
        'details': event_dump
    }
    return incident


def fetch_incidents(client: Client, regions: str, start_time: int = None, end_time: int = None):
    if start_time and end_time:
        print_debug_msg(f'Start fetching incidents between {start_time} and {end_time}.')
    else:
        print_debug_msg('Start fetching most recent incidents')

    notification_map = client.get_dlp_incidents(regions=regions, start_time=start_time, end_time=end_time)
    incidents = []
    for region, notifications in notification_map.items():
        for notification in notifications:
            incident = create_incident(notification, region)
            incidents.append(incident)
    return incidents


def is_reset_triggered():
    """
    Checks if reset of integration context have been made by the user.
    Because fetch is long running execution, user communicates with us
    by calling 'pan-dlp-reset-last-run' command which sets reset flag in
    context.

    Returns:
        (bool):
        - True if reset flag was set. If 'handle_reset' is true, also resets integration context.
        - False if reset flag was not found in integration context.
    """
    ctx = get_integration_context()
    if ctx and RESET_KEY in ctx:
        print_debug_msg('Reset fetch-incidents.')
        set_integration_context({'samples': '[]'})
        return True
    return False


def fetch_notifications(client: Client, regions: str):
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get(ACCESS_TOKEN)
    if access_token:
        client.set_access_token(access_token)

    incidents = fetch_incidents(
        client=client,
        regions=regions
    )
    print_debug_msg(f"Received {len(incidents)} incidents")
    if not is_reset_triggered():
        demisto.createIncidents(incidents)
        new_ctx = {
            ACCESS_TOKEN: client.access_token,
            'samples': incidents
        }
        demisto.setIntegrationContext(new_ctx)
    elif len(incidents) > 0:
        print_debug_msg(f"Skipped {len(incidents)} incidents because of reset")


def long_running_execution_command(client: Client, params: Dict):
    """
    Long running execution of fetching incidents from Palo Alto Networks Enterprise DLP.
    Will continue to fetch in an infinite loop.
    Args:
        params (Dict): Demisto params.

    """
    demisto.setIntegrationContext({ACCESS_TOKEN: ''})
    regions = demisto.get(params, 'dlp_regions', '')
    sleep_time = FETCH_SLEEP
    last_time_sleep_interval_queries = math.floor(datetime.now().timestamp())
    while True:
        try:
            current_time = math.floor(datetime.now().timestamp())
            fetch_notifications(client, regions)

            if current_time - last_time_sleep_interval_queries > 5 * 60:
                overriden_sleep_time = client.query_for_sleep_time()
                last_time_sleep_interval_queries = current_time
                if overriden_sleep_time:
                    print_debug_msg(f'Setting sleep time to value from backend: {overriden_sleep_time}')
                    sleep_time = overriden_sleep_time

        except Exception:
            demisto.error('Error occurred during long running loop')
            demisto.error(traceback.format_exc())

        finally:
            print_debug_msg('Finished fetch loop')
            time.sleep(sleep_time)


def exemption_eligible_command(args: dict, params: dict) -> CommandResults:
    data_profile = args.get('data_profile')
    eligible_list = params.get('dlp_exemptible_list', '')
    if eligible_list == '*':
        eligible = True
    else:
        eligible = data_profile in eligible_list

    result = {
        'eligible': eligible
    }
    return CommandResults(
        outputs_prefix='DLP.exemption',
        outputs_key_field='eligible',
        outputs=result
    )


def slack_bot_message_command(args: dict, params: dict):
    message_template = params.get('dlp_slack_message', '')
    template = Template(message_template)
    message = template.substitute(
        user=args.get('user'),
        file_name=args.get('file_name'),
        data_profile_name=args.get('data_profile_name'),
        app_name=args.get('app_name'),
        snippets=args.get('snippets', ""))
    result = {
        'message': message
    }
    return CommandResults(
        outputs_prefix='DLP.slack_message',
        outputs_key_field='slack_message',
        outputs=result
    )


def fetch_incidents_command() -> List[Dict]:
    """
    Fetch incidents implemented, for mapping purposes only.
    Returns list of samples saved by long running execution.

    Returns:
        (List[Dict]): List of incidents samples.
    """
    ctx = get_integration_context()
    return ctx.get('samples', [])


def reset_last_run_command() -> str:
    """
    Puts the reset flag inside integration context.
    Returns:
        (str): 'fetch-incidents was reset successfully'.
    """
    ctx = get_integration_context()
    ctx[RESET_KEY] = 'true'
    set_to_integration_context_with_retries(ctx)
    return 'fetch-incidents was reset successfully.'


def main():
    """ Main Function"""
    try:
        demisto.info('Command is %s' % (demisto.command(),))
        params = demisto.params()
        print_debug_msg('Received parameters')
        print_debug_msg(params)
        credentials = params.get('credentials')

        client = Client(BASE_URL, credentials, params.get('insecure'), params.get('proxy'))
        args = demisto.args()
        if demisto.command() == 'pan-dlp-get-report':
            report_id = args.get('report_id')
            fetch_snippets = argToBoolean(args.get('fetch_snippets'))
            report_json, status_code = client.get_dlp_report(report_id, fetch_snippets)
            return_results(parse_dlp_report(report_json))
        elif demisto.command() == 'fetch-incidents':
            demisto.incidents(fetch_incidents_command())
        elif demisto.command() == 'long-running-execution':
            long_running_execution_command(client, params)
        elif demisto.command() == 'pan-dlp-update-incident':
            return_results(update_incident_command(client, args))
        elif demisto.command() == 'pan-dlp-exemption-eligible':
            return_results(exemption_eligible_command(args, params))
        elif demisto.command() == 'pan-dlp-slack-message':
            return_results(slack_bot_message_command(args, params))
        elif demisto.command() == 'pan-dlp-reset-last-run':
            return_results(reset_last_run_command())
        elif demisto.command() == "test-module":
            test(client)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
