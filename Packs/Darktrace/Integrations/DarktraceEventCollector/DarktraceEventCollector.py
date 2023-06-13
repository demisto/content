import hashlib
import hmac
import json
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple, cast

import dateparser
import demistomock as demisto
import urllib3
from CommonServerPython import *

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

# Disable insecure warnings
urllib3.disable_warnings()

"""*****CONSTANTS*****"""

VENDOR = 'Darktrace'
PRODUCT = 'Darktrace'
MODEL_BREACH_ENDPOINT = '/modelbreaches'
DARKTRACE_API_ERRORS = {
    'SIGNATURE_ERROR': 'API Signature Error. You have invalid credentials in your config.',
    'DATE_ERROR': 'API Date Error. Check that the time on this machine matches that of the Darktrace instance.',
    'ENDPOINT_ERROR': f'Invalid Endpoint.',
    'PRIVILEGE_ERROR': 'User has insufficient permissions to access the API endpoint.',
    'UNDETERMINED_ERROR': f'Darktrace was unable to process your request.',
    'FAILED_TO_PARSE': 'N/A'
}

"""*****CLIENT CLASS*****
Wraps all the code that interacts with the Darktrace API."""


class Client(BaseClient):
    """Client class to interact with the Darktrace API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get(self, query_uri: str, params: Dict[str, str] = None):
        """Handles Darktrace GET API calls"""
        return self._darktrace_api_call(query_uri, method='GET', params=params)

    def post(self, query_uri: str, data: dict = None, json: dict = None):
        """Handles Darktrace POST API calls"""
        return self._darktrace_api_call(query_uri, method='POST', data=data, json=json)

    def _darktrace_api_call(
        self,
        query_uri: str,
        method: str,
        params: dict = None,
        data: dict = None,
        json: dict = None,
        headers: Dict[str, str] = None,
    ):
        """Handles Darktrace API calls"""
        headers = {
            **self._create_headers(query_uri, params or data or json or None, is_json=bool(json)),
            **(headers or {}),
        }

        try:
            res = self._http_request(
                method,
                url_suffix=query_uri,
                params=params,
                data=data,
                json_data=json,
                resp_type='response',
                headers=headers,
                error_handler=self.error_handler,
            )
            if res.status_code not in [200, 204]:
                raise Exception('Your request failed with the following error: ' + str(res.content)
                                + '. Response Status code: ' + str(res.status_code))
        except Exception as e:
            raise Exception(e)
        try:
            return res.json()
        except Exception as e:
            raise ValueError(
                f'Failed to process the API response - {str(e)}'
            )

    def error_handler(self, res: requests.Response):
        """Handles authentication errors"""
        if res.status_code == 400:
            values = res.json().values()
            if 'API SIGNATURE ERROR' in values:
                raise Exception(DARKTRACE_API_ERRORS['SIGNATURE_ERROR'])
            elif 'API DATE ERROR' in values:
                raise Exception(DARKTRACE_API_ERRORS['DATE_ERROR'])
        elif res.status_code == 302:
            # Valid hmac but invalid endpoint (should not happen)
            if res.text == 'Found. Redirecting to /login':
                raise Exception(DARKTRACE_API_ERRORS['ENDPOINT_ERROR'])
            # Insufficient permissions but valid hmac
            elif res.text == 'Found. Redirecting to /403':
                raise Exception(DARKTRACE_API_ERRORS['PRIVILEGE_ERROR'])
        elif res.status_code >= 300:
            raise Exception(DARKTRACE_API_ERRORS['UNDETERMINED_ERROR'])

    def _create_headers(self, query_uri: str, query_data: dict = None, is_json: bool = False) -> Dict[str, str]:
        """Create headers required for successful authentication"""
        public_token, _ = self._auth
        date = (datetime.now(timezone.utc)).isoformat(timespec="auto")
        signature = _create_signature(self._auth, query_uri, date, query_data, is_json=is_json)
        return {'DTAPI-Token': public_token, 'DTAPI-Date': date, 'DTAPI-Signature': signature}

    def get_events(self, start_time, end_time) -> List[Dict[str, Any]]:
        """
        """
        query_uri = MODEL_BREACH_ENDPOINT
        params = {'starttime': start_time, 'endtime': end_time, 'expandenums': True, 'includeacknowledged': True}
        return self.get(query_uri, params)


"""*****HELPER FUNCTIONS****"""


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])


def check_required_fields(args, *fields):
    """Checks that required fields are found, raises a value error otherwise"""
    for field in fields:
        if field not in args:
            raise ValueError(f'Argument error could not find {field} in {args}')


def _create_signature(tokens: tuple, query_uri: str, date: str, query_data: dict = None, is_json: bool = False) -> str:
    """Create signature from Darktrace private token"""
    public_token, private_token = tokens
    if is_json:
        query_string = f'?{json.dumps(query_data)}'
    else:
        query_string = f'?{stringify_data(query_data)}' if query_data else ''

    return hmac.new(
        private_token.encode('ASCII'),
        f'{query_uri}{query_string}\n{public_token}\n{date}'.encode('ASCII'),
        hashlib.sha1,
    ).hexdigest()


def format_JSON_for_model_breach(modelbreach: Dict[str, Any], details: bool = False) -> Dict[str, Any]:
    """Formats JSON for get-model-breach command
    :type modelbreach: ``Dict[str, Any]``
    :param modelbreach: JSON model breach as returned by API for fetch incident
    :return: Filtered JSON containing only relevant fields for context
    :rtype: ``Dict[str, Any]``
    """
    relevant_info = {}

    relevant_info['pbid'] = modelbreach.get('pbid')
    relevant_info['commentCount'] = modelbreach.get('commentCount', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    relevant_info['time'] = modelbreach.get('time', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    formatted_score = str(round(modelbreach.get('score', 0) * 100, 1))
    relevant_info['score'] = f'{formatted_score} %'

    if details:
        relevant_info['triggeredComponents'] = modelbreach.get('triggeredComponents', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])

    device_info = {}
    if 'device' in modelbreach:
        device = modelbreach['device']
        device_info['did'] = str(device.get('did', DARKTRACE_API_ERRORS['FAILED_TO_PARSE']))
        device_info['macaddress'] = device.get('macaddress', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        device_info['vendor'] = device.get('vendor', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        device_info['ip'] = device.get('ip', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        device_info['hostname'] = device.get('hostname', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        device_info['devicelabel'] = device.get('devicelabel', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        device_info['credentials'] = device.get('credentials', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        device_info['deviceType'] = device.get('typename', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    relevant_info['device'] = device_info

    model_info = {}
    if 'then' in modelbreach['model']:
        modelthen = modelbreach['model']['then']
        model_info['name'] = modelthen.get('name', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        model_info['pid'] = modelthen.get('pid', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        model_info['uuid'] = modelthen.get('uuid', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        model_info['tags'] = modelthen.get('tags', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        model_info['priority'] = modelthen.get('priority', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        model_info['category'] = modelthen.get('category', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
        model_info['description'] = modelthen.get('description', DARKTRACE_API_ERRORS['FAILED_TO_PARSE']).replace('\\n', '')
    relevant_info['model'] = model_info
    relevant_info['link'] = params.get('url', '') + '/#modelbreach/' + str(relevant_info['pbid'])
    return relevant_info


def _compute_xsoar_severity(dt_categry: str) -> int:
    """Translates Darktrace category into XSOAR Severity"""
    if 'nformational' in dt_categry:
        return 2
    if 'uspicious' in dt_categry:
        return 3
    if 'ritical' in dt_categry:
        return 4
    return 1


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client, first_fetch_time: Optional[float]) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :type client: ``Client``
    :param client:
        Darktrace Client
    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        First fetch time
    :return:
        A message to indicate the integration works as it is supposed to
    :rtype: ``str``
    """
    try:
        client.get_events(start_time=first_fetch_time, end_time=datetime.now().timestamp())
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client, max_alerts: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], min_score: int) -> Tuple[Dict[str, int], List[dict]]:
    """This function retrieves new model breaches every minute. It will use last_run
    to save the timestamp of the last incident it processed. If last_run is not provided,
    it should use the integration parameter first_fetch to determine when to start fetching
    the first time.
    :type client: ``Client``
    :param Client: Darktrace client to use
    :type max_alerts: ``int``
    :param max_alerts: Maximum numbers of incidents per fetch
    :type last_run: ``Dict[str, int]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch
    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents
    :type min_score: ``int``
    :param min_score:
        min_score of model breaches to pull. Range is [0,100]
    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    model_breach_alerts = client.search_model_breaches(
        min_score=min_score / 100,  # Scale the min score from [0,100] to [0 to 1] for API calls
        start_time=last_fetch  # time of last fetch or initialization time
    )

    for alert in model_breach_alerts:
        # If no created_time set is as epoch (0). We use time in ms, which
        # matches the Darktrace API response
        incident_created_time = int(alert.get('creationTime', 0))
        alert['time'] = timestamp_to_datestring(incident_created_time)

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue
        pbid = str(alert['pbid'])
        title = alert['model']['then']['name']
        incident_name = f'DT modelId #{pbid}: {title}'

        formatted_JSON = format_JSON_for_model_breach(alert, details=True)
        xsoar_severity = _compute_xsoar_severity(alert['model']['then']['category'])

        incident = {
            'name': incident_name,
            'occurred': timestamp_to_datestring(incident_created_time),
            'rawJSON': json.dumps(formatted_JSON),
            'severity': xsoar_severity
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

        if len(incidents) >= max_alerts:
            break

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def get_model_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """darktrace-get-breach command: Returns a Darktrace model breach

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'pbid')
    pbid = str(args.get('pbid', None))
    model_breach = client.get_model_breach(pbid=pbid)

    if 'time' in model_breach:
        created_time = int(model_breach.get('time', '0'))
        model_breach['time'] = timestamp_to_datestring(created_time)

    # Format JSON for Context Output
    formatted_output = format_JSON_for_model_breach(model_breach)

    readable_output = tableToMarkdown(f'Darktrace Model Breach {pbid}', formatted_output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=formatted_output
    )


def get_model_breach_connections_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_model_breach_connections_command command: Returns a Darktrace model breach connections

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'pbid')
    pbid = str(args['pbid'])
    count = str(int(args['count']) + 1)
    endtime = str(args.get('endtime', time.time() * 1000))
    model_breach_details_response = (client.get_model_breach_connections(pbid=pbid, endtime=endtime, count=count,
                                                                         offset=str(args['offset'])))
    if len(model_breach_details_response) > 1:
        connection_details = model_breach_details_response[1:]
        headers = sorted(connection_details[-1].keys())
        readable_output = tableToMarkdown(f'Darktrace Model Breach {pbid} Details', connection_details,
                                          headers=headers, removeNull=True)

    else:
        connection_details = [{'response': 'Unable to locate connection details for this Model Breach'}]
        readable_output = connection_details

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pid',
        outputs=connection_details
    )


def get_model_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_model_command command: Returns a Darktrace model information

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'uuid')
    uuid = str(args['uuid'])
    res = client.get_model(uuid=uuid)
    readable_output = tableToMarkdown(f'Darktrace Model {uuid}', res)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.Model',
        outputs_key_field='uuid',
        outputs=res
    )


def get_model_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_model_component_command command: Returns a Darktrace model component information

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'cid')
    cid = str(args.get('cid', None))
    res = client.get_model_component(cid=cid)
    readable_output = tableToMarkdown(f'Darktrace Component {cid}', res)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.Model.Component',
        outputs_key_field='cid',
        outputs=res
    )


def get_model_breach_comments_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """darktrace-get-comments command: Returns the comments on the model breach

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'pbid')
    pbid = str(args.get('pbid', None))

    comments = client.get_model_breach_comments(pbid=pbid)

    model_breach_comments = {'comments': comments}
    if not len(comments):
        model_breach_comments['message'] = [{'comment': 'No comments in Darktrace on this model breach.'}]

    for comment in model_breach_comments['comments']:
        if 'time' in comment:
            created_time = int(comment.get('time', '0'))
            comment['time'] = timestamp_to_datestring(created_time)
        comment['pbid'] = int(pbid)

    readable_output = tableToMarkdown(f'Darktrace Model Breach {pbid} Comments', model_breach_comments['comments'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach.Comment',
        outputs_key_field='message',
        outputs=model_breach_comments
    )


def acknowledge_model_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """acknowledge_model_breach_command: Acknowledges the model breach based on pbid

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'pbid')
    pbid = str(args['pbid'])

    ack_response = client.acknowledge_model_breach(pbid=pbid)
    if ack_response["response"] != "SUCCESS":
        ack_response["response"] = "Model Breach already acknowledged."
    else:
        ack_response["response"] = "Successfully acknowledged."
    ack_response['pbid'] = int(pbid)
    ack_response['acknowledged'] = "True"
    readable_output = tableToMarkdown(f'Model Breach {pbid} Acknowledged', ack_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=ack_response
    )


def unacknowledge_model_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """acknowledge_model_breach_command: Unacknowledges the model breach based on pbid

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'pbid')
    pbid = str(args.get('pbid', None))

    ack_response = client.unacknowledge_model_breach(pbid=pbid)
    if ack_response['response'] != 'SUCCESS':
        ack_response['response'] = 'Model Breach already unacknowledged.'
    else:
        ack_response['response'] = 'Successfully unacknowledged.'
    ack_response['pbid'] = int(pbid)
    ack_response['acknowledged'] = 'False'
    readable_output = tableToMarkdown(f'Model Breach {pbid} Acknowledged', ack_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=ack_response
    )


def post_comment_to_model_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """post_comment_to_model_breach_command: posts a comment to a model breach

    :type client: ``Client``
    :param Client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """
    check_required_fields(args, 'pbid', 'message')
    pbid = str(args['pbid'])
    comment = str(args['message'])

    post_comment_response = client.post_comment_to_model_breach(pbid=pbid, comment=comment)

    if post_comment_response['response'] != 'SUCCESS':
        post_comment_response['response'] = 'Failed to comment Model Breach.'
    else:
        post_comment_response['response'] = 'Successfully Uploaded Comment.'
    post_comment_response['pbid'] = int(pbid)
    post_comment_response['message'] = str(comment)
    post_comment_response['commented'] = 'True'

    readable_output = tableToMarkdown(f'Model Breach {pbid} Acknowledged', post_comment_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=post_comment_response
    )


def fetch_events(client: Client, max_fetch: int, first_fetch_time: float, last_run: dict):
    """
    Args:


    Returns:

    """
    start_time = last_run.get('last_fetch_time', first_fetch_time)
    end_time = datetime.now()
    demisto.debug(f'Getting events from: {timestamp_to_datestring(start_time)}, till: {end_time}')
    retrieve_events = client.get_events(start_time, end_time.timestamp())
    demisto.debug(f'Fetched {len(retrieve_events)} events.')
    # filtering events
    retrieve_events = retrieve_events[:max_fetch]
    demisto.debug(f'Limiting to {len(retrieve_events)} events.')
    # setting last run object
    if retrieve_events:
        # extracting last fetch time and last fetched events.
        last_fetch_time = retrieve_events[-1].get('time')
        last_fetched_events = [event.get('pbid') for event in retrieve_events]
        demisto.debug(f'Setting last run to: {timestamp_to_datestring(last_fetch_time)}')
        last_run = {'last_fetch_time': retrieve_events[-1].get('time'),
                    'last_fetched_events': last_fetched_events}

    return retrieve_events, last_run


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params.get('base_url')
    public_api_token = params.get('public_creds', {}).get('password', '')
    private_api_token = params.get('private_creds', {}).get('password', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch_time = arg_to_datetime(arg=params.get('first_fetch', '3 days'),
                                       arg_name='First fetch time',
                                       required=True).timestamp()
    tokens = (public_api_token, private_api_token)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth=tokens
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, first_fetch_time))

        elif demisto.command() == 'fetch-events':
            last_run = demisto.getLastRun()
            events, new_last_run = fetch_events(client=client,
                                                max_fetch=max_fetch,
                                                first_fetch_time=first_fetch_time,  # type: ignore
                                                last_run=last_run)
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            if new_last_run:
                demisto.setLastRun(new_last_run)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
