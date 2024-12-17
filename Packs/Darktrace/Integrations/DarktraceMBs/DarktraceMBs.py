import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import hmac
import json
import time
import traceback
from datetime import datetime, UTC
from typing import Any, cast
from collections.abc import Mapping

import dateparser
import urllib3

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

# Disable insecure warnings
urllib3.disable_warnings()

"""*****CONSTANTS*****"""
MODEL_BREACH_ENDPOINT = '/modelbreaches'
DETAILS_ENDPOINT = '/details'
MODEL_BREACH_CONFIG_ENDPOINT = '/models'
COMPONENTS_ENDPOINT = '/components'
MODEL_BREACH_COMMENT_ENDPOINT = "/mbcomments"
ACK_BREACH = "/acknowledge"
UNACK_BREACH = "/unacknowledge"
COMMENT_BREACH = "/comments"

MIN_SCORE_TO_FETCH = 0
MAX_INCIDENTS_TO_FETCH = 50
PLEASE_CONTACT = "Please create a ticket on the Darktrace Customer Portal."

DARKTRACE_API_ERRORS = {
    'SIGNATURE_ERROR': 'API Signature Error. You have invalid credentials in your config.',
    'DATE_ERROR': 'API Date Error. Check that the time on this machine matches that of the Darktrace instance.',
    'ENDPOINT_ERROR': f'Invalid Endpoint. {PLEASE_CONTACT}',
    'PRIVILEGE_ERROR': 'User has insufficient permissions to access the API endpoint.',
    'UNDETERMINED_ERROR': f'Darktrace was unable to process your request. {PLEASE_CONTACT}',
    'DATA_NOT_FOUND_ERROR': 'Darktrace was unable to find the requested data.',
    'FAILED_TO_PARSE': 'N/A'
}

DARKTRACE_LOGIN = '<title>Log In | Darktrace</title>'


"""*****CLIENT CLASS*****
Wraps all the code that interacts with the Darktrace API."""


class Client(BaseClient):
    """Client class to interact with the Darktrace API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get(self, query_uri: str, params: dict[str, str] = None):
        """Handles Darktrace GET API calls"""
        return self._darktrace_api_call(query_uri, method='GET', params=params)

    def post(self, query_uri: str, data: dict = None, json: dict = None):
        """Handles Darktrace POST API calls"""
        response = self._darktrace_api_call(query_uri, method='POST', data=data, json=json)
        if isinstance(response, list) and len(response):
            response = response[0]
        return response

    def _darktrace_api_call(
        self,
        query_uri: str,
        method: str,
        params: dict = None,
        data: dict = None,
        json: dict = None,
        headers: dict[str, str] = None,
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

        res_str = res.content.decode('utf-8')
        if DARKTRACE_LOGIN in res_str:
            raise Exception(DARKTRACE_API_ERRORS['PRIVILEGE_ERROR'])

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
                raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['SIGNATURE_ERROR']}")
            elif 'API DATE ERROR' in values:
                raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['DATE_ERROR']}")
        elif res.status_code == 404:
            try:
                res_json = res.json()
                error = res_json.get("error", False)
                if error:
                    raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['DATA_NOT_FOUND_ERROR']} {error}.")
                else:
                    raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['DATA_NOT_FOUND_ERROR']}")
            except json.JSONDecodeError:
                raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['DATA_NOT_FOUND_ERROR']}")
        elif res.status_code == 302:
            # Valid hmac but invalid endpoint (should not happen)
            if res.text == 'Found. Redirecting to /login':
                raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['ENDPOINT_ERROR']}")
            # Insufficient permissions but valid hmac
            elif res.text == 'Found. Redirecting to /403':
                raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['PRIVILEGE_ERROR']}")
        elif res.status_code >= 300:
            raise Exception(f"{res.status_code} - {DARKTRACE_API_ERRORS['UNDETERMINED_ERROR']}")

    def _create_headers(self, query_uri: str, query_data: dict = None, is_json: bool = False) -> dict[str, str]:
        """Create headers required for successful authentication"""
        public_token, _ = self._auth
        date = (datetime.now(UTC)).isoformat(timespec="auto")
        signature = _create_signature(self._auth, query_uri, date, query_data, is_json=is_json)
        return {'DTAPI-Token': public_token, 'DTAPI-Date': date, 'DTAPI-Signature': signature}

    def get_model_breach(self, pbid: str) -> dict[str, Any]:
        """Searches for a single Darktrace model breach alerts using '/modelbreaches?pbid=<pbid>'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        query_uri = MODEL_BREACH_ENDPOINT
        params = {'pbid': pbid, 'deviceattop': 'true'}
        return self.get(query_uri, params)

    def get_model_breach_connections(self, pbid: str, endtime: str, count: str, offset: str) -> list[dict[str, Any]]:
        """Searches for a single Darktrace model breach connections using '/details' endpoint
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :type endtime: ``str``
        :param endtime: End time for query
        :type count: ``str``
        :param count: way to sort response
        :type offset: ``str``
        :param offset: offset for paginated response
        :return: dict containing the found Darktrace model breach
        :rtype: ``List[Dict[str, Any]]``
        """
        query_uri = DETAILS_ENDPOINT
        params = {
            'endTime': endtime,
            'order': 'desc',
            'includetotalbytes': 'true',
            'offset': offset,
            'count': count,
            'pbid': pbid
        }
        return self.get(query_uri, params)

    def get_model(self, uuid: str) -> dict[str, Any]:
        """Pulls a model configuration from /models endpoint
        :type uuid: ``str``
        :param uuid: Model ID
        :return: Dict containing the model information
        :rtype: ``Dict[str, Any]``
        """
        query_uri = f'{MODEL_BREACH_CONFIG_ENDPOINT}'
        params = {'uuid': uuid}
        return self.get(query_uri, params)

    def get_model_component(self, cid: str) -> dict[str, Any]:
        """Pulls a model component from /components endpoint
        :type cid: ``str``
        :param cid: component ID
        :return: Dict containing the component information
        :rtype: ``Dict[str, Any]``
        """
        query_uri = COMPONENTS_ENDPOINT
        params = {'cid': cid}
        return self.get(query_uri, params)

    def get_model_breach_comments(self, pbid: str) -> list[dict[str, Any]]:
        """Searches for comments on a modelbreach using '/modelbreaches/<pbid>/comments'
        :type pbid: ``str``
        :param pbid: Model breach ID
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``Dict[str, Any]``
        """
        query_uri = MODEL_BREACH_COMMENT_ENDPOINT
        params = {'pbid': pbid}
        return self.get(query_uri, params)

    def acknowledge_model_breach(self, pbid: str) -> dict[str, Any]:
        """Acknowledges a modelbreach using '/modelbreaches/<pbid>/acknowledge?acknowledge=true'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``Dict[str, Any]``
        """
        query_uri = f'{MODEL_BREACH_ENDPOINT}/{pbid}{ACK_BREACH}'
        return self.post(query_uri, json={"acknowledge": "true"})

    def unacknowledge_model_breach(self, pbid: str) -> dict[str, Any]:
        """Unacknowledges a modelbreach using '/modelbreaches/<pbid>/unacknowledge?unacknowledge=true'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ```Dict[str, Any]``
        """
        query_uri = f"{MODEL_BREACH_ENDPOINT}/{pbid}{UNACK_BREACH}"
        return self.post(query_uri, json={"unacknowledge": "true"})

    def post_comment_to_model_breach(self, pbid: str, comment: str) -> dict[str, Any]:
        """Posts a comment to a model breach'
        :type pbid: ``str``
        :param pbid: Model breach ID
        :type comment: ``str``
        :param comment: Comment messsage to be posted
        :return: Response from post comment command
        :rtype: ``Dict[str, Any]``
        """
        query_uri = f'{MODEL_BREACH_ENDPOINT}/{pbid}{COMMENT_BREACH}'
        return self.post(query_uri, json={'message': comment})

    def search_model_breaches(self, min_score: float, start_time: int | None) -> list[dict[str, Any]]:
        """Searches for Darktrace alerts using the '/modelbreaches' API endpoint
        :type min_score: ``float``
        :param min_score: min score of the alert to search for. Range [0, 1].
        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search
        :return: list containing the found Darktrace model breaches as dicts
        :rtype: ``List[Dict[str, Any]]``
        """
        query_uri = MODEL_BREACH_ENDPOINT
        params = {
            'minscore': str(min_score),
            'starttime': str(start_time),
            'minimal': 'false',
            'deviceattop': 'true'
        }
        return self.get(query_uri, params)


"""*****HELPER FUNCTIONS****"""


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)
    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.
    :type arg: ``Any``
    :param arg: argument to convert
    :type arg_name: ``str``
    :param arg_name: argument name
    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None
    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing \'{arg_name}\'')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, int | float):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: \'{arg_name}\'')


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


def format_JSON_for_model_breach(modelbreach: dict[str, Any], details: bool = False) -> dict[str, Any]:
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
    relevant_info['link'] = demisto.params().get('url', '') + '/#modelbreach/' + str(relevant_info['pbid'])
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


def test_module(client: Client, first_fetch_time: int | None) -> str:
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
        client.search_model_breaches(min_score=0, start_time=first_fetch_time)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client, max_alerts: int, last_run: dict[str, int],
                    first_fetch_time: int | None, min_score: int) -> tuple[dict[str, int], list[dict]]:
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
    incidents: list[dict[str, Any]] = []

    model_breach_alerts = client.search_model_breaches(
        min_score=min_score / 100,    # Scale the min score from [0,100] to [0 to 1] for API calls
        start_time=last_fetch       # time of last fetch or initialization time
    )

    for alert in model_breach_alerts:
        # If no created_time set is as epoch (0). We use time in ms, which
        # matches the Darktrace API response
        incident_created_time = int(alert.get('creationTime', 0))
        alert['time'] = timestamp_to_datestring(incident_created_time)

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch and incident_created_time <= last_fetch:
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


def get_model_breach_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_model_breach_connections_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_model_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_model_component_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_model_breach_comments_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def acknowledge_model_breach_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    ack_output: Dict[str, Any] = {}

    if "response" in ack_response and ack_response["response"] == "SUCCESS":
        ack_output["response"] = "Successfully acknowledged."
    elif "replicate" in ack_response and ack_response['replicate'] is True:
        ack_output["response"] = "Successfully acknowledged."
    else:
        ack_output["response"] = "Model Breach already acknowledged."
    ack_output['pbid'] = int(pbid)
    readable_output = tableToMarkdown(f'Model Breach {pbid} Acknowledged', ack_output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=ack_output
    )


def unacknowledge_model_breach_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    ack_output: Dict[str, Any] = {}

    if "response" in ack_response and ack_response["response"] == "SUCCESS":
        ack_output["response"] = "Successfully unacknowledged."
    elif "replicate" in ack_response and ack_response['replicate'] is True:
        ack_output["response"] = "Successfully unacknowledged."
    else:
        ack_output["response"] = "Model Breach already unacknowledged."
    ack_output['pbid'] = int(pbid)
    readable_output = tableToMarkdown(f'Model Breach {pbid} Unacknowledged', ack_output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=ack_output
    )


def post_comment_to_model_breach_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    output_response: dict[str, str | int] = {}
    if post_comment_response.get("message", False):
        output_response['response'] = 'Successfully posted comment.'
        output_response['pbid'] = int(pbid)
        output_response['message'] = str(comment)
    else:
        output_response['response'] = 'Failed to post comment.'

    readable_output = tableToMarkdown(f'Model Breach {pbid}', output_response)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=output_response
    )


"""*****MAIN FUNCTIONS****
Takes care of reading the integration parameters via
the ``demisto.params()`` function, initializes the Client class and checks the
different options provided to ``demisto.commands()``, to invoke the correct
command function passing to it ``demisto.args()`` and returning the data to
``return_results()``. If implemented, ``main()`` also invokes the function
``fetch_incidents()``with the right parameters and passes the outputs to the
``demisto.incidents()`` function. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.
"""


def main() -> None:     # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """

    # Collect Darktrace URL
    base_url = demisto.params().get('url')

    # Collect API tokens
    public_api_token = demisto.params().get('publicApiKey', '')
    private_api_token = demisto.params().get('privateApiKey', '')
    tokens = (public_api_token, private_api_token)

    # Client class inherits from BaseClient, so SSL verification is
    # handled out of the box by it. Pass ``verify_certificate`` to
    # the Client constructor.
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '1 day'),
        arg_name='First fetch time',
        required=True
    )

    # Client class inherits from BaseClient, so system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # ``demisto.debug()``, ``demisto.info()``, prints information in the XSOAR server log.
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

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.

            # Convert the argument to an int using helper function or set to MIN_SCORE_TO_FETCH
            min_score = arg_to_number(
                arg=demisto.params().get('min_score'),
                arg_name='min_score',
                required=False
            )
            if not min_score or min_score < MIN_SCORE_TO_FETCH:
                min_score = MIN_SCORE_TO_FETCH

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_alerts = arg_to_number(
                arg=demisto.params().get('max_fetch', MAX_INCIDENTS_TO_FETCH),
                arg_name='max_fetch',
                required=False
            )
            if not max_alerts or max_alerts > MAX_INCIDENTS_TO_FETCH:
                max_alerts = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_alerts=max_alerts,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                min_score=min_score
            )

            # Use the variables defined above as the outputs of fetch_incidents to set up the next call and create incidents:
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif demisto.command() == 'darktrace-get-model-breach':
            return_results(get_model_breach_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-model-breach-connections':
            return_results(get_model_breach_connections_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-model':
            return_results(get_model_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-model-component':
            return_results(get_model_component_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-model-breach-comments':
            return_results(get_model_breach_comments_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-acknowledge-model-breach':
            return_results(acknowledge_model_breach_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-unacknowledge-model-breach':
            return_results(unacknowledge_model_breach_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-post-comment-to-model-breach':
            return_results(post_comment_to_model_breach_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
