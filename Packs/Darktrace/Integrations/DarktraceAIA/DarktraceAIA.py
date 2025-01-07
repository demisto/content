import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import hmac
import json
import traceback
from datetime import datetime, UTC
from typing import Any, cast
from collections.abc import Mapping

import dateparser
import urllib3

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

# Disable insecure warnings
urllib3.disable_warnings()

AI_ANALYST_ENDPOINT = '/aianalyst/incidentevents'
AI_ANALYST_COMMENT_ENDPOINT = '/aianalyst/incident/comments'
AI_ANALYST_POST_COMMENT_ENDPOINT = '/aianalyst/comments'
AI_ANALYST_ACKNOWLEDGE_ENDPOINT = '/aianalyst/acknowledge'
AI_ANALYST_UNACKNOWLEDGE_ENDPOINT = '/aianalyst/unacknowledge'
AI_ANALYST_GROUP_ENDPOINT = '/aianalyst/groups'
MIN_SCORE_TO_FETCH = 0
MAX_INCIDENTS_TO_FETCH = 50
PLEASE_CONTACT = "Please contact your Darktrace representative."

DARKTRACE_API_ERRORS = {
    'SIGNATURE_ERROR': 'API Signature Error. You have invalid credentials in your config.',
    'DATE_ERROR': 'API Date Error. Check that the time on this machine matches that of the Darktrace instance.',
    'ENDPOINT_ERROR': f'Invalid Endpoint. - {PLEASE_CONTACT}',
    'PRIVILEGE_ERROR': 'User has insufficient permissions to access the API endpoint.',
    'UNDETERMINED_ERROR': f'Darktrace was unable to process your request - {PLEASE_CONTACT}',
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

    def get(self, query_uri: str, params: dict[str, str] = None):
        """Handles Darktrace GET API calls"""
        return self._darktrace_api_call(query_uri, method="GET", params=params)

    def post(self, query_uri: str, data: dict = None, json: dict = None):
        """Handles Darktrace POST API calls"""
        return self._darktrace_api_call(query_uri, method="POST", data=data, json=json)

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
            if "API SIGNATURE ERROR" in values:
                raise Exception(DARKTRACE_API_ERRORS['SIGNATURE_ERROR'])
            elif "API DATE ERROR" in values:
                raise Exception(DARKTRACE_API_ERRORS['DATE_ERROR'])
        elif res.status_code == 302:
            # Valid hmac but invalid endpoint (should not happen)
            if res.text == "Found. Redirecting to /login":
                raise Exception(DARKTRACE_API_ERRORS['ENDPOINT_ERROR'])
            # Insufficient permissions but valid hmac
            elif res.text == "Found. Redirecting to /403":
                raise Exception(DARKTRACE_API_ERRORS['PRIVILEGE_ERROR'])
        elif res.status_code >= 300:
            raise Exception(DARKTRACE_API_ERRORS['UNDETERMINED_ERROR'])

    def _create_headers(self, query_uri: str, query_data: dict = None, is_json: bool = False) -> dict[str, str]:
        """Create headers required for successful authentication"""
        public_token, _ = self._auth
        date = (datetime.now(UTC)).isoformat(timespec="auto")
        signature = _create_signature(self._auth, query_uri, date, query_data, is_json=is_json)
        return {"DTAPI-Token": public_token, "DTAPI-Date": date, "DTAPI-Signature": signature}

    def get_ai_analyst_incident_event(self, event_id: str) -> list[dict[str, Any]]:
        """Searches for a single AI Analyst Incident alerts using '/incidentevents?uuid=<event_id>'
        :type event_id: ``str``
        :param event_id:  unique event identifier
        :return: list with incident event information
        :rtype: ``List[Dict[str, Any]]``
        """
        return self.get(AI_ANALYST_ENDPOINT, params={"uuid": event_id})

    def search_ai_analyst_incident_events(self, min_score: int, start_time: int | None) -> list[dict[str, Any]]:
        """Searches all AI Analyst Incident alerts from a certain date and score'
        :type min_score: ``str``
        :param min_score:  minimum score for data to be pulled
        :type start_time: ``str``
        :param start_time:  start date to pull data from
        :return: list of incident events information as a dictionary
        :rtype: ``List[Dict[str, Any]]``
        """
        query_uri = AI_ANALYST_ENDPOINT
        params = {
            'mingroupscore': str(min_score),
            'starttime': str(start_time)
        }
        return self.get(query_uri, params)

    def get_comments_for_ai_analyst_incident_event(self, event_id: str) -> dict[str, Any]:
        """ Returns all comments for a specified incident event id
        :type event_id: ``str``
        :param event_id:  unique event identifier
        :return: dict with list of comments for an event id
        :rtype: ``Dict[str, Any]``
        """
        query_uri = AI_ANALYST_COMMENT_ENDPOINT
        params = {
            'incident_id': str(event_id),
        }
        return self.get(query_uri, params)

    def post_comment_to_ai_analyst_incident_event(self, event_id: str, comment: str) -> dict[str, Any]:
        """ Posts a message to an incident event id
        :type event_id: ``str``
        :param event_id:  unique event identifier
        :type comment: ``str``
        :param comment:  message to be posted
        :return: response from post message action
        :rtype: ``Dict[str, Any]``
        """
        query_uri = AI_ANALYST_COMMENT_ENDPOINT
        body = {
            'incident_id': str(event_id),
            'message': comment
        }
        return self.post(query_uri, json=body)

    def acknowledge_ai_analyst_incident_event(self, event_id: str) -> dict[str, Any]:
        """ acknowledges an incident event
        :type event_id: ``str``
        :param event_id:  unique event identifier
        :return: response from event acknowledgement
        :rtype: ``Dict[str, Any]``
        """
        query_uri = AI_ANALYST_ACKNOWLEDGE_ENDPOINT
        return self.post(query_uri, data={'uuid': str(event_id)})

    def unacknowledge_ai_analyst_incident_event(self, event_id: str) -> dict[str, Any]:
        """ unacknowledges an incident event
        :type event_id: ``str``
        :param event_id:  unique event identifier
        :return: response from event unacknowledgement
        :rtype: ``Dict[str, Any]``
        """
        query_uri = AI_ANALYST_UNACKNOWLEDGE_ENDPOINT
        return self.post(query_uri, data={'uuid': str(event_id)})

    def get_ai_analyst_incident_group_from_eventId(self, event_id: str) -> list[dict[str, Any]]:
        """Searches for a single AI Analyst Group alerts using '/groups?uuid=<event_id>'
        :type event_id: ``str``
        :param event_id:  unique event identifier
        :return: list with incident event information
        :rtype: ``List[Dict[str, Any]]``
        """
        return self.get(AI_ANALYST_GROUP_ENDPOINT, params={"uuid": event_id})


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
            raise ValueError(f'Missing "{arg_name}"')
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
    raise ValueError(f'Invalid date: "{arg_name}"')


def _create_signature(tokens: tuple, query_uri: str, date: str, query_data: dict = None, is_json: bool = False) -> str:
    """Create signature from Darktrace private token"""
    public_token, private_token = tokens
    if is_json:
        query_string = f"?{json.dumps(query_data)}"
    else:
        query_string = f"?{stringify_data(query_data)}" if query_data else ""

    return hmac.new(
        private_token.encode("ASCII"),
        f"{query_uri}{query_string}\n{public_token}\n{date}".encode("ASCII"),
        hashlib.sha1,
    ).hexdigest()


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])


def format_JSON_for_ai_analyst_incident(aia_incident: dict[str, Any], details: bool = False) -> dict[str, Any]:
    """Formats JSON for get-ai-incident-event command
    :type aia_incident: ``Dict[str, Any]``
    :param aia_incident: JSON incident event as returned by API for fetch incident
    :return: Filtered JSON containing only relevant fields for context
    :rtype: ``Dict[str, Any]``
    """
    relevant_info = {}
    relevant_info['eventId'] = aia_incident.get('id', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    time = aia_incident.get('createdAt', 0)
    relevant_info['createdAt'] = timestamp_to_datestring(time)
    relevant_info['title'] = aia_incident.get('title', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    relevant_info['mitreTactics'] = aia_incident.get('mitreTactics', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    relevant_info['score'] = str(aia_incident.get('aiaScore', 0)) + '%'
    relevant_info['category'] = aia_incident.get('category', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    relevant_info['summary'] = aia_incident['summary'].replace('\\n', '')
    relevant_info['groupId'] = aia_incident['currentGroup']
    if details:
        relevant_info['details'] = aia_incident['details']
    relevant_info['devices'] = aia_incident.get('breachDevices', DARKTRACE_API_ERRORS['FAILED_TO_PARSE'])
    if 'relatedBreaches' in aia_incident:
        model_breaches = aia_incident['relatedBreaches']
        model_breach_info = {}
        for i in range(len(model_breaches)):
            model_breaches[i]['timestamp'] = timestamp_to_datestring(model_breaches[i]['timestamp'])
            model_breach_info[str(i)] = model_breaches[i]
    relevant_info['modelBreaches'] = model_breach_info
    relevant_info['link'] = demisto.params().get('url', '') + '/#aiagroup/' + str(relevant_info['groupId'])
    return relevant_info


def _compute_xsoar_severity(category: str) -> int:
    """Translates Darktrace category into XSOAR Severity"""
    if category == 'compliance':
        return 1
    if category == 'informational':
        return 2
    if category == 'suspicious':
        return 3
    return 4


def check_required_fields(args, *fields):
    """Checks that required fields are found, raises a value error otherwise"""
    for field in fields:
        if field not in args:
            raise ValueError(f'Argument error could not find {field} in {args}')


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
        client.search_ai_analyst_incident_events(min_score=0, start_time=first_fetch_time)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client, max_alerts: int, last_run: dict[str, int],
                    first_fetch_time: int | None, min_score: int) -> tuple[dict[str, int], list[dict]]:
    """This function retrieves new ai analyst incident event every minute. It will use last_run
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
        min_score of incident events to pull. Range is [0,100]
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

    ai_analyst_alerts = client.search_ai_analyst_incident_events(
        min_score=min_score,    # Scale the min score from [0,100] to [0 to 1] for API calls
        start_time=last_fetch       # time of last fetch or initialization time
    )

    for alert in ai_analyst_alerts:
        incident_created_time = int(alert.get('createdAt', 0))
        alert['time'] = timestamp_to_datestring(incident_created_time)
        if last_fetch and incident_created_time <= last_fetch:
            continue
        id = str(alert['id'])
        title = str(alert['title'])
        incident_name = f'DT eventId #{id}: {title}'

        formatted_JSON = format_JSON_for_ai_analyst_incident(alert, details=True)
        xsoar_severity = _compute_xsoar_severity(alert['groupCategory'])
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


def get_ai_analyst_incident_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """get-ai-analyst-incident-event-command: Returns a Darktrace incident event details

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
    check_required_fields(args, 'eventId')
    eventId = str(args['eventId'])
    aia_response = client.get_ai_analyst_incident_event(eventId)[0]

    if 'time' in aia_response:
        created_time = int(aia_response.get('createdAt', '0'))
        aia_response['time'] = timestamp_to_datestring(created_time)

    # Format JSON for Context Output
    formatted_output = format_JSON_for_ai_analyst_incident(aia_response)

    readable_output = tableToMarkdown(f'Darktrace AI Analyst Incident {eventId}', formatted_output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AIAnalyst',
        outputs_key_field='Darktrace.AIAnalyst.eventId',
        outputs=formatted_output
    )


def get_comments_for_ai_analyst_incident_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """darktrace-get-comments-for-ai-analyst-incident-event-command: Returns all comments associated with an
    incident event.

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
    check_required_fields(args, 'eventId')
    id = str(args['eventId'])
    aia_comment_response = client.get_comments_for_ai_analyst_incident_event(id)
    comments = aia_comment_response.get('comments', 'No comments available')
    if comments:
        for comment in comments:
            comment['eventId'] = comment.pop('incident_id')
            comment['time'] = timestamp_to_datestring(comment['time'])
        readable_output = tableToMarkdown(f'Darktrace AIA Comments for {id}', comments)
    else:
        unsuccessful_message = [{'response': 'unable to get comments'}]
        readable_output = tableToMarkdown(f'Darktrace AIA Comments for {id}', unsuccessful_message)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AIAnalyst',
        outputs_key_field='Darktrace.AIAnalyst.eventId',
        outputs=aia_comment_response
    )


def post_comment_to_ai_analyst_incident_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """darktrace-post-comment-to-ai-analyst-incident-event-command: Posts a comment to an ai analyst event

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
    check_required_fields(args, 'eventId', 'comment')
    eventId = str(args['eventId'])
    message = str(args['comment'])
    aia_comment_response = client.post_comment_to_ai_analyst_incident_event(eventId, message)
    output = {}
    if aia_comment_response['aianalyst'] == 'SUCCESS':
        output['commented'] = 'True'
        output['response'] = 'Successfully Uploaded Comment'
    else:
        output['commented'] = 'False'
        output['response'] = 'Unable to Upload comment'
    output['eventId'] = eventId
    output['message'] = message
    readable_output = tableToMarkdown('Darktrace AIA Post Comment Response', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AIAnalyst',
        outputs_key_field='Darktrace.AIAnalyst.eventId',
        outputs=output
    )


def acknowledge_ai_analyst_incident_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """acknowledge-ai-analyst-incident-event-command: Acknowledges an ai analyst event

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
    check_required_fields(args, 'eventId')
    eventId = str(args['eventId'])
    aia_ack_response = client.acknowledge_ai_analyst_incident_event(eventId)
    output = {}
    if aia_ack_response['aianalyst'] == 'SUCCESS':
        output['acknowledged'] = 'True'
        output['response'] = 'Incident Event Successfully Acknowledged'
    else:
        output['acknowledged'] = 'False'
        output['response'] = 'Unable to acknowledge event. '
    output['eventId'] = eventId
    readable_output = tableToMarkdown('Darktrace AIA Post Comment Response', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AIAnalyst',
        outputs_key_field='Darktrace.AIAnalyst.eventId',
        outputs=output
    )


def unacknowledge_ai_analyst_incident_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """unacknowledge-ai-analyst-incident-event-command: Unacknowledges an ai analyst event

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
    check_required_fields(args, 'eventId')
    eventId = args['eventId']
    aia_ack_response = client.unacknowledge_ai_analyst_incident_event(str(args['eventId']))
    output = {}
    if aia_ack_response['aianalyst'] == 'SUCCESS':
        output['unacknowledged'] = 'True'
        output['response'] = 'Incident Event Successfully Unacknowledged'
    else:
        output['unacknowledged'] = 'False'
        output['response'] = 'Unable to Unacknowledge event. '
    output['eventId'] = eventId
    readable_output = tableToMarkdown('Darktrace AIA Unacknowledgement Response', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AIAnalyst',
        outputs_key_field='Darktrace.AIAnalyst.eventId',
        outputs=output
    )


def get__ai_analyst_incident_group_from_eventId_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """darktrace-get-incident-group-from-event: Pulls all events belonging to the same investigation group.

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
    check_required_fields(args, 'eventId')
    aia_ack_response = client.get_ai_analyst_incident_group_from_eventId(str(args['eventId']))
    output = {}
    if len(aia_ack_response):
        group_response = aia_ack_response[0]
        output['groupId'] = group_response['id']
        output['groupScore'] = round(group_response['groupScore'], 1)
        output['groupCategory'] = group_response['category']
        output['acknowledged'] = group_response['acknowledged']
        output['mitreTactics'] = group_response['mitreTactics']
        for event in group_response['incidentEvents']:
            event['eventId'] = event.pop('uuid')
            event['deviceId'] = event.pop('triggerDid')
            event['start'] = timestamp_to_datestring(event['start'])
        output['incidentEvents'] = group_response['incidentEvents']

    readable_output = tableToMarkdown('Darktrace AIA Group Information', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AIAnalyst',
        outputs_key_field='groupId',
        outputs=output
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

        elif demisto.command() == 'darktrace-get-ai-analyst-incident-event':
            return_results(get_ai_analyst_incident_event_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-comments-for-ai-analyst-incident-event':
            return_results(get_comments_for_ai_analyst_incident_event_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-post-comment-to-ai-analyst-incident-event':
            return_results(post_comment_to_ai_analyst_incident_event_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-acknowledge-ai-analyst-incident-event':
            return_results(acknowledge_ai_analyst_incident_event_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-unacknowledge-ai-analyst-incident-event':
            return_results(unacknowledge_ai_analyst_incident_event_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-ai-analyst-incident-group-from-eventId':
            return_results(get__ai_analyst_incident_group_from_eventId_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
