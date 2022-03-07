import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import urllib.parse
from typing import Dict
from enum import Enum
from datetime import datetime
import math
from string import Template

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
MAX_ATTEMPTS = 3
BASE_URL = 'https://api.dlp.paloaltonetworks.com/v1/'
STAGING_BASE_URL = 'https://aa420c196330b4eb2bbf89ece2d68461-852397286.us-west-2.elb.amazonaws.com/v1/'
REPORT_URL = 'public/report/{}'
INCIDENTS_URL = 'public/incident-notifications'
REFRESH_TOKEN_URL = 'public/oauth/refreshToken'
UPDATE_INCIDENT_URL = 'public/incident-feedback'
FETCH_SLEEP = 5  # sleep between fetches (in seconds)
LAST_FETCH_TIME = 'last_fetch_time'
DEFAULT_FIRST_FETCH = '60 minutes'
ACCESS_TOKEN = 'access_token'


class FeedbackStatus(Enum):
    PENDING_RESPONSE = 'PENDING_RESPONSE'
    CONFIRMED_SENSITIVE = 'CONFIRMED_SENSITIVE'
    CONFIRMED_FALSE_POSITIVE = 'CONFIRMED_FALSE_POSITIVE'
    EXCEPTION_REQUESTED = 'EXCEPTION_REQUESTED'
    OPERATIONAL_ERROR = 'OPERATIONAL_ERROR'


class Client(BaseClient):

    def __init__(self, url, refresh_token, access_token, insecure, proxy):
        super().__init__(base_url=url, headers=None, verify=not insecure, proxy=proxy)
        self.refresh_token = refresh_token
        self.access_token = access_token

    def _refresh_token(self):
        """Refreshes Access Token"""
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json"
        }
        params = {
            "refresh_token": self.refresh_token
        }
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

        if res.status_code < 200 or res.status_code >= 300:
            raise DemistoException("Request to {} failed with status code {}".format(url_suffix, res.status_code))

        result_json = {} if res.status_code == 204 else res.json()
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

        if res.status_code < 200 or res.status_code >= 300:
            print_debug_msg(f"Request to {url_suffix} failed with status code {res.status_code}")
            raise DemistoException(f"Request to {url_suffix} failed with status code {res.status_code}")

        result_json = {}
        if res.status_code != 204:
            try:
                result_json = res.json()
            except json.decoder.JSONDecodeError:
                result_json = {}

        return result_json, res.status_code

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

    def get_dlp_incidents(self, start_time: int, end_time: int, regions: str) -> dict:
        url = INCIDENTS_URL
        params = {}
        if regions:
            params['regions'] = regions;
        if start_time:
            params['start_timestamp'] = start_time
        if end_time:
            params['end_timestamp'] = end_time
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"
        resp, status_code = self._get_dlp_api_call(url)
        return resp
        # incidents = []
        # for event in events:
        #     incident_creation_time = dateparser.parse(events[-1]['createdAt'])
        #     incident = {
        #         'name': f'Palo Alto Networks DLP incident {event["incidentId"]}',  # name is required field, must be set
        #         'occurred': incident_creation_time.isoformat(),  # must be string of a format ISO8601
        #         'rawJSON': json.dumps(event)
        #         # the original event, this will allow mapping of the event in the mapping stage. Don't forget to `json.dumps`
        #     }
        #     incidents.append(incident)
        #
        # latest_created_time = dateparser.parse(events[-1]['createdAt'])
        # latest_created_time = latest_created_time.strftime(DATE_FORMAT)
        # next_run = {'last_fetch': latest_created_time, 'id': events[-1]['incidentId']}
        # if call_from_test:
        #     # Returning None
        #     return {}, []
        # return next_run, incidents

    def update_dlp_incident(self, incident_id: str, feedback: FeedbackStatus, user_id: str, region: str):
        """
                Update Incident with user provided feedback
                Args:
                    incident_id: The id of the incident to update
                    feedback: 'business_justified', 'true_positive' or 'false_positive'

                Returns: DLP Incident json
                """
        payload = {
            'user_id': user_id
        }
        url = f'{UPDATE_INCIDENT_URL}/{incident_id}?feedback_type={feedback.value}&region={region}'
        return  self._post_dlp_api_call(url, payload)

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


def parse_dlp_report(report_json):
    """
    Parses DLP Report for display
    Args:
        report_json: DLP report json

    Returns: DLP report results
    """
    data_patterns = parse_data_patterns(report_json)
    results = CommandResults(
        outputs_prefix='DLP.Report',
        outputs_key_field='DataPatternName',
        outputs=data_patterns,
        readable_output=convert_to_human_readable(data_patterns),
        raw_response=report_json
    )
    return_results(results)


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


def update_incident(client: Client, incident_id: str, feedback: str, user_id: str, region: str):
    feedback_enum = FeedbackStatus[feedback.upper()]
    result_json, status = client.update_dlp_incident(incident_id, feedback_enum, user_id, region)
    result = {
        'success': status == 200,
        'feedback': feedback_enum.value
    }
    results = CommandResults(
        outputs_prefix='DLP.IncidentUpdate',
        outputs_key_field='feedback',
        outputs=result
    )
    demisto.results(results.to_context())


def fetch_incidents(client: Client, start_time: int, end_time: int, regions: str):
    print_debug_msg(f'Start fetching incidents between {start_time} and {end_time}.')

    incident_map = client.get_dlp_incidents(start_time, end_time, regions)
    incidents = []
    for region in incident_map:
        raw_incidents = incident_map[region]
        for raw_incident in raw_incidents:
            raw_incident['region'] = region
            incident_creation_time = dateparser.parse(raw_incident['createdAt'])
            event_dump  = json.dumps(raw_incident)
            incident = {
              'name': f'Palo Alto Networks DLP Incident {raw_incident["incidentId"]}',  # name is required field, must be set
              'type': 'Data Loss Prevention',
              'occurred': incident_creation_time.isoformat(),  # must be string of a format ISO8601
              'rawJSON': event_dump,
              'details': event_dump
            }
            incidents.append(incident)
    return incidents


def long_running_execution_command(params: Dict):
    """
    Long running execution of fetching incidents from Palo Alto Networks Enterprise DLP.
    Will continue to fetch in an infinite loop.
    Args:
        params (Dict): Demisto params.

    """
    regions = params.get('dlp_regions')
    refresh_token = params.get('refresh_token')
    url = BASE_URL if params.get('env') == 'prod' else STAGING_BASE_URL
    while True:
        try:
            integration_context = demisto.getIntegrationContext()
            last_fetch_time = integration_context.get(LAST_FETCH_TIME)
            now = math.floor(datetime.now().timestamp())
            last_fetch_time = now - 30 if not last_fetch_time else last_fetch_time
            end_time = now
            access_token = integration_context.get(ACCESS_TOKEN)
            access_token = params.get('access_token') if not access_token else access_token
            client = Client(url, refresh_token, access_token, params.get('insecure'), params.get('proxy'))
            incidents = fetch_incidents(
                client=client,
                start_time=last_fetch_time,
                end_time=end_time,
                regions=regions
            )
            print_debug_msg(f"Received {len(incidents)} incidents")
            # new_end_time = math.floor(datetime.now().timestamp()) if not end_time else end_time
            demisto.setIntegrationContext({LAST_FETCH_TIME: end_time, ACCESS_TOKEN: client.access_token})
            demisto.createIncidents(incidents)

        except Exception:
            demisto.error('Error occurred during long running loop')
            demisto.error(traceback.format_exc())

        finally:
            print_debug_msg('Finished fetch loop')
            time.sleep(FETCH_SLEEP)


def exemption_eligible(args: dict, params: dict):
    data_profile = args.get('data_profile')
    eligible_list = params.get('dlp_exemptible_list')
    eligible = data_profile in eligible_list
    result = {
        'eligible': eligible
    }
    results = CommandResults(
        outputs_prefix='DLP.exemption',
        outputs_key_field='eligible',
        outputs=result
    )
    demisto.results(results.to_context())

def slack_bot_message(args: dict, params: dict):
    message_template = params.get('dlp_slack_message')
    template = Template(message_template)
    message = template.substitute(file_name=args.get('file_name'),
                                  data_profile_name=args.get('data_profile_name'),
                                  snippets=args.get('snippets', ""))
    result = {
        'message': message
    }
    results = CommandResults(
        outputs_prefix='DLP.slack_message',
        outputs_key_field='slack_message',
        outputs=result
    )
    demisto.results(results.to_context())

def main():
    """ Main Function"""
    try:
        demisto.info('Command is %s' % (demisto.command(),))
        params = demisto.params()
        access_token = params.get('access_token')
        refresh_token = params.get('refresh_token')
        url = BASE_URL if params.get('env') == 'prod' else STAGING_BASE_URL
        client = Client(url, refresh_token, access_token, params.get('insecure'), params.get('proxy'))
        args = demisto.args()
        if demisto.command() == 'pan-dlp-get-report':
            report_id = args.get('report_id')
            fetch_snippets = argToBoolean(args.get('fetch_snippets'))
            report_json, status_code = client.get_dlp_report(report_id, fetch_snippets)
            parse_dlp_report(report_json)
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            last_fetch_time = last_run.get(LAST_FETCH_TIME) if last_run else None
            now = math.floor(datetime.now().timestamp())
            last_fetch_time = now - 3600 if not last_fetch_time else last_fetch_time
            incidents = fetch_incidents(
                client=client,
                start_time=last_fetch_time,
                end_time=now,
                regions=params.get('dlp_regions')
            )

            demisto.setLastRun({LAST_FETCH_TIME: now})
            demisto.incidents(incidents)
        elif demisto.command() == 'long-running-execution':
            long_running_execution_command(params)
        elif demisto.command() == 'pan-dlp-update-incident':
            incident_id = args.get('incident_id')
            feedback = args.get('feedback')
            user_id = args.get('user_id')
            region = args.get('region')
            update_incident(client, incident_id, feedback, user_id, region)
        elif demisto.command() == 'pan-dlp-exemption-eligible':
            exemption_eligible(args, params)
        elif demisto.command() == 'pan-dlp-slack-message':
            slack_bot_message(args, params)
        elif demisto.command() == "test-module":
            test(client)

    except Exception as e:
        LOG(e)
        return_error(str(e))
    finally:
        demisto.info(
            f'{demisto.command()} completed.')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
