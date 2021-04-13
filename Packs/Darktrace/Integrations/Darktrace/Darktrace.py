import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests
import dateparser
from datetime import datetime
import traceback
from typing import Any, Dict, Tuple, List, Optional, cast
from copy import copy

import hmac
import hashlib

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""*****CONSTANTS*****"""

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
MIN_SCORE_TO_FETCH = 0

# For API call mapping
PARAMS_DICTIONARY = {
    'did': 'did',
    'data_type': 'datatype',
    'external_domain': 'externaldomain',
    'full_device_details': 'fulldevicedetails',
    'destination_did': 'oid',
    'show_all_graph_data': 'showallgraphdata',
    'num_similar_devices': 'similardevices',
    'breach_id': 'pbid',
    'host_name': 'hostname',
    'order_by': 'orderBy',
    'max_results': 'count'
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

    def get_modelbreach(self, pbid):
        """Searches for a single Darktrace model breach alerts using '/modelbreaches?pbid=<pbid>'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        request = f"/modelbreaches?pbid={pbid}"
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers
        )

    def get_modelbreach_comments(self, pbid):
        """Searches for comments on a modelbreach using '/modelbreaches/<pbid>/comments'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        request = "/modelbreaches/" + pbid + "/comments"
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers
        )

    def acknowledge_breach(self, pbid):
        """Acknowledges a modelbreach using '/modelbreaches/<pbid>/acknowledge?acknowledge=true'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        request = "/modelbreaches/" + pbid + "/acknowledge?acknowledge=true"
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='POST',
            url_suffix=request,
            headers=http_headers,
            data={"acknowledge": "true"}
        )

    def unacknowledge_breach(self, pbid):
        """Unacknowledges a modelbreach using '/modelbreaches/<pbid>/unacknowledge?unacknowledge=true'
        :type pbid: ``str``
        :param pbid: Model breach ID of the model breach to get
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        request = "/modelbreaches/" + pbid + "/unacknowledge?unacknowledge=true"
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='POST',
            url_suffix=request,
            headers=http_headers,
            data={"unacknowledge": "true"}
        )

    def list_similar_devices(self, did, max_results):
        """Returns a list of similar devices using '/similardevices'
        :type did: ``str``
        :param did: Device ID of device
        :type max_results: ``str``
        :param max_results: Max # of results to return
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        request = "/similardevices?did=" + did + "&count=" + max_results
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers,
        )

    def get_external_endpoint_details(self, endpoint_type, endpoint_value, additional_info, devices, score):
        """Returns information from Darktrace about external endpoints using '/endpointdetails'
        :type endpoint_type: ``str``
        :param endpoint_type: Type of endpoint, IP or hostname
        :type endpoint_value: ``str``
        :param endpoint_value: Value of IP or hostname
        :type additional_info: ``str``
        :param additional_info: Whether to include additional info
        :type devices: ``str``
        :param devices: Whether to include additional devices that connected to the endpoint
        :type score: ``str``
        :param score: Whether to include external endpoint score
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        request = f"/endpointdetails?{endpoint_type}={endpoint_value}&additionalinfo={additional_info}" \
                  f"&devices={devices}&score={score}"
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers,
        )

    def get_device_connection_info(self, did, data_type, external_domain, destination_did,
                                   show_all_graph_data, full_device_details, num_similar_devices):
        """Returns information from Darktrace about graphical connection data for devices using '/deviceinfo'
        :type did: ``str``
        :param did: Darktrace Device ID
        :type data_type: ``str``
        :param data_type: Whether to return data for either connections (connections), data size out (sizeout) or
        data size in (sizein)
        :type external_domain: ``str``
        :param external_domain: Whether to restrict external data to a particular domain name.
        :type destination_did: ``str``
        :param destination_did: Darktrace Device DID of destination device to restrict data to.
        :type show_all_graph_data: ``str``
        :param show_all_graph_data: Whether to return an entry for all time intervals
        :type full_device_details: ``str``
        :param full_device_details: Whether to return the full device detail objects
        :type num_similar_devices: ``str``
        :param num_similar_devices: Num similar devices to include
        :return: list containing the connection info as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        query_dict = copy(locals())
        query_dict.pop('self')
        query_string = create_query_from_dict(query_dict)
        request = "/deviceinfo" + query_string
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers,
        )

    def get_device_identity_info(self, max_results, order_by, order, query):
        """Returns information from Darktrace about identifying  data for devices using '/devicesearch'
        :type max_results: ``str``
        :param max_results: Darktrace Device ID
        :type order_by: ``str``
        :param order_by: Whether to return data for either connections (connections), data size out (sizeout) or
        data size in (sizein)
        :type order: ``str``
        :param order: Whether to restrict external data to a particular domain name.
        :type query: ``str``
        :param query: Darktrace Device DID of destination device to restrict data to.
        :return: list containing the device info as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        query_dict = copy(locals())
        query_dict.pop('self')
        query_string = create_query_from_dict(query_dict)
        request = "/devicesearch" + query_string
        http_headers = get_headers(self._auth, request)
        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers,
        )

    def get_entity_details(self, max_results, offset, query_list):
        """Returns information from Darktrace about entities using '/details'
        :type max_results: ``int``
        :param max_results: Darktrace Device ID
        :type offset: ``int``
        :param offset: Offset index to start returning queries from.
        :type query: ``list``
        :param query: List-separated query
        :return: list containing the device info as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        query_string = create_query_from_list(query_list)
        request = '/details' + query_string
        http_headers = get_headers(self._auth, request)

        res = self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers
        )

        if not isinstance(res, list):
            raise Exception(f'Error getting results:\n {res}')
        if offset > len(res):
            raise Exception(f'Offset argument: {offset}, is grater than the amount of results: {len(res)}')
        truncated_response = res[offset:offset + max_results]

        return truncated_response, res

    def search_modelbreaches(self, min_score: float,
                             start_time: Optional[int]) -> List[Dict[str, Any]]:
        """Searches for Darktrace alerts using the '/modelbreaches' API endpoint
        :type min_score: ``float``
        :param min_score: min score of the alert to search for. Range [0, 1].
        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search
        :return: list containing the found Darktrace model breaches as dicts
        :rtype: ``List[Dict[str, Any]]``
        """
        request = '/modelbreaches'
        request = request + '?minscore=' + str(min_score)
        request = request + '&starttime=' + str(start_time)

        http_headers = get_headers(self._auth, request)

        return self._http_request(
            method='GET',
            url_suffix=request,
            headers=http_headers
        )


"""*****HELPER FUNCTIONS****"""


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
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
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int
    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.
    :type arg: ``Any``
    :param arg: argument to convert
    :type arg_name: ``str``
    :param arg_name: argument name
    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None
    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def get_headers(tokens: tuple, request: str) -> Dict[str, str]:
    """Returns the appropriate HTTP Header for token authentication.
    :type tokens: ``tuple``
    :param tokens: Tuple containing the PUBLIC and PRIVATE API tokens
    :type request: ``str``
    :param request: API request being made, ex: /modelbreaches
    :return:
        returns a Dictionary of the necessary HTTP Headers
    :rtype: ``Dict[str, str]``
    """
    d = datetime.utcnow()
    now = d.strftime('%Y%m%dT%H%M%S')
    public = tokens[0]
    private = tokens[1]
    maccer = hmac.new(private.encode('ASCII'),
                      (request + '\n' + public + '\n' + now).encode('ASCII'), hashlib.sha1)
    sig = maccer.hexdigest()
    headers = {'DTAPI-Token': public, 'DTAPI-Date': now, 'DTAPI-Signature': sig}
    return headers


def create_query_from_dict(param_dict: Dict[str, str]):
    """Returns a query string based on a provided dict.
    :type param_dict: ``Dict[str, str]``
    :param param_dict: Dictionary of parameters
    :return:
        returns the query string
    :rtype: ``str``
    """
    query_string = '?'
    for key, val in param_dict.items():
        if val:
            query_string = query_string + f'{PARAMS_DICTIONARY.get(key, key)}={val}&'
    # remove the last '&' in the string
    return query_string[:-1] if param_dict else ''


def create_query_from_list(param_list: Dict[str, str]):
    """Returns a query string based on a provided list.
    :type param_list: ``List``
    :param param_list: List of parameters
    :return:
        returns the query string
    :rtype: ``str``
    """
    translated_list = [PARAMS_DICTIONARY.get(param, param) for param in param_list]
    query = '?' + '&'.join(translated_list)
    return query if param_list else ''


def format_JSON_for_fetch_incidents(modelbreach: Dict[str, Any]) -> Dict[str, Any]:
    """Formats JSON for fetch incidents.
    :type modelbreach: ``Dict[str, Any]``
    :param modelbreach: JSON model breach as returned by API for fetch incident
    :return: Filtered JSON containing only relevant fields for context
    :rtype: ``Dict[str, Any]``
    """
    relevant_info = {}

    relevant_info['commentCount'] = modelbreach['commentCount'] if 'commentCount' in modelbreach else 'No comment count'
    relevant_info['pbid'] = modelbreach['pbid'] if 'pbid' in modelbreach else 'No Darktrace pbid'
    relevant_info['time'] = modelbreach['time'] if 'time' in modelbreach else 'No Darktrace model breach time'
    relevant_info['score'] = modelbreach['score'] if 'score' in modelbreach else 'No Darktrace model breach score'
    relevant_info['triggeredComponents'] = modelbreach['triggeredComponents'] if 'triggeredComponents' in modelbreach\
        else 'No Darktrace triggeredComponents'

    if 'device' in modelbreach:
        device = modelbreach['device']
        device_info = {}
        device_info['did'] = str(device['did']) if 'did' in device else 'No DID in Darktrace'
        device_info['macaddress'] = device['macaddress'] if 'macaddress' in device else 'No MAC address in Darktrace'
        device_info['vendor'] = device['vendor'] if 'vendor' in device and device['vendor'] != '' \
            else 'No device vendor in Darktrace'
        device_info['ip'] = device['ip'] if 'ip' in device else 'No device IP in Darktrace'
        device_info['hostname'] = device['hostname'] if 'hostname' in device else 'No device hostname in Darktrace'
        device_info['devicelabel'] = device['devicelabel']if 'devicelabel' in device else 'No device label in Darktrace'
    relevant_info['device'] = device_info

    if 'then' in modelbreach['model']:
        modelthen = modelbreach['model']['then']
        model_info = {}
        model_info['name'] = modelthen['name'] if 'name' in modelthen else 'No Darktrace model name'
        model_info['pid'] = modelthen['pid'] if 'pid' in modelthen else 'No Darktrace model pid'
        model_info['uuid'] = modelthen['uuid'] if 'uuid' in modelthen else 'No Darktrace model uuid'
        model_info['tags'] = modelthen['tags'] if 'tags' in modelthen else 'No Darktrace model tags'
        model_info['priority'] = modelthen['priority'] if 'priority' in modelthen else 'No Darktrace model priority'
        model_info['description'] = modelthen['description'] if 'description' in modelthen else 'No Darktrace model description'

    relevant_info['model'] = model_info

    return relevant_info


def format_JSON_for_modelbreach(modelbreach: Dict[str, Any]) -> Dict[str, Any]:
    """Formats JSON for get-breach command
    :type modelbreach: ``Dict[str, Any]``
    :param modelbreach: JSON model breach as returned by API for fetch incident
    :return: Filtered JSON containing only relevant fields for context
    :rtype: ``Dict[str, Any]``
    """
    relevant_info = {}

    relevant_info['commentCount'] = modelbreach['commentCount'] if 'commentCount' in modelbreach else 'No comment count'
    relevant_info['pbid'] = modelbreach['pbid'] if 'pbid' in modelbreach else 'No Darktrace pbid'
    relevant_info['time'] = modelbreach['time'] if 'time' in modelbreach else 'No Darktrace model breach time'
    relevant_info['score'] = modelbreach['score'] if 'score' in modelbreach else 'No Darktrace model breach score'

    if 'device' in modelbreach:
        device = modelbreach['device']
        device_info = {}
        device_info['did'] = str(device['did']) if 'did' in device else 'No DID in Darktrace'
        device_info['macaddress'] = device['macaddress'] if 'macaddress' in device else 'No MAC address in Darktrace'
        device_info['vendor'] = device['vendor'] if 'vendor' in device and device['vendor'] != '' \
            else 'No device vendor in Darktrace'
        device_info['ip'] = device['ip'] if 'ip' in device else 'No device IP in Darktrace'
        device_info['hostname'] = device['hostname'] if 'hostname' in device else 'No device hostname in Darktrace'
        device_info['devicelabel'] = device['devicelabel']if 'devicelabel' in device else 'No device label in Darktrace'
    relevant_info['device'] = device_info

    if 'then' in modelbreach['model']:
        modelthen = modelbreach['model']['then']
        model_info = {}
        model_info['name'] = modelthen['name'] if 'name' in modelthen else 'No Darktrace model name'
        model_info['pid'] = modelthen['pid'] if 'pid' in modelthen else 'No Darktrace model pid'
        model_info['uuid'] = modelthen['uuid'] if 'uuid' in modelthen else 'No Darktrace model uuid'
        model_info['tags'] = modelthen['tags'] if len(modelthen['tags']) > 0 else ['No Darktrace model tags']
        model_info['priority'] = modelthen['priority'] if 'priority' in modelthen else 'No Darktrace model priority'
        model_info['description'] = modelthen['description'] if 'description' in modelthen else 'No Darktrace model description'

    relevant_info['model'] = model_info

    return relevant_info


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client, first_fetch_time: Optional[int]) -> str:
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
        client.search_modelbreaches(min_score=0, start_time=first_fetch_time)

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

    alerts = client.search_modelbreaches(
        min_score=min_score / 100,    # Scale the min score from [0,100] to [0 to 1] for API calls
        start_time=last_fetch       # time of last fetch or initialization time
    )

    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms, which
        # matches the Darktrace API response
        incident_created_time = int(alert.get('time', '0'))
        alert['time'] = timestamp_to_datestring(incident_created_time)

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue

        incident_name = 'Darktrace Model Breach #' + str(alert['pbid'])

        formatted_JSON = format_JSON_for_fetch_incidents(alert)

        # The incident dict is initialized with a few mandatory fields:
        # name: the incident name
        # occurred: the time on when the incident occurred, in ISO8601 format
        # we use timestamp_to_datestring() from CommonServerPython.py to
        # handle the conversion.
        # rawJSON: everything else is packed in a string via json.dumps()
        # and is included in rawJSON. It will be used later for classification
        # and mapping inside XSOAR.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSOAR specific severity (int 1 to 4)

        incident = {
            'name': incident_name,
            'occurred': timestamp_to_datestring(incident_created_time),
            'rawJSON': json.dumps(formatted_JSON)
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


def get_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    pbid = str(args.get('pbid', None))
    if not pbid:
        raise ValueError('Darktrace Model Breach ID not specified')

    model_breach = client.get_modelbreach(pbid=pbid)

    if 'time' in model_breach:
        created_time = int(model_breach.get('time', '0'))
        model_breach['time'] = timestamp_to_datestring(created_time)

    # Format JSON for Context Output
    formatted_output = format_JSON_for_modelbreach(model_breach)

    readable_output = tableToMarkdown(f'Darktrace Model Breach {pbid}', formatted_output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=formatted_output
    )


def get_comments_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    pbid = str(args.get('pbid', None))
    if not pbid:
        raise ValueError('Darktrace Model Breach ID not specified')

    comments = client.get_modelbreach_comments(pbid=pbid)
    model_breach_comments = {"comments": comments}

    if len(comments) == 0:
        model_breach_comments["comments"] = [{"message": "No comments in Darktrace on this model breach."}]

    for comment in model_breach_comments["comments"]:
        if 'time' in comment:
            created_time = int(comment.get('time', '0'))
            comment['time'] = timestamp_to_datestring(created_time)
        comment['pbid'] = int(pbid)

    readable_output = tableToMarkdown(f'Darktrace Model Breach {pbid} Comments', model_breach_comments["comments"])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pid',
        outputs=model_breach_comments
    )


def acknowledge_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """acknowledge_breach_command: Acknowledges the model breach based on pbid

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
    pbid = str(args.get('pbid', None))
    if not pbid:
        raise ValueError('Darktrace Model Breach ID not specified')

    ack_response = client.acknowledge_breach(pbid=pbid)
    if ack_response["response"] != "SUCCESS":
        ack_response["response"] = "Model Breach already acknowledged."
    else:
        ack_response["response"] = "Successfully acknowledged."
    ack_output: Dict[str, Any] = {}
    ack_output['pbid'] = int(pbid)
    ack_output['acknowledged'] = "true"
    readable_output = tableToMarkdown(f'Model Breach {pbid} Acknowledged', ack_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=ack_output
    )


def unacknowledge_breach_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """acknowledge_breach_command: Unacknowledges the model breach based on pbid

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
    pbid = str(args.get('pbid', None))
    if not pbid:
        raise ValueError('Darktrace Model Breach ID not specified')

    ack_response = client.unacknowledge_breach(pbid=pbid)
    if ack_response["response"] != "SUCCESS":
        ack_response["response"] = "Model Breach already unacknowledged."
    else:
        ack_response["response"] = "Successfully unacknowledged."
    ack_output: Dict[str, Any] = {}
    ack_output['pbid'] = int(pbid)
    ack_output['acknowledged'] = "false"
    readable_output = tableToMarkdown(f'Model Breach {pbid} Acknowledged', ack_response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ModelBreach',
        outputs_key_field='pbid',
        outputs=ack_output
    )


def list_similar_devices_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """list_similar_devices_command: Returns a list of similar devices to a device specified
    by Darktrace DID

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
    did = str(args.get('did', None))
    max_results = str(args.get('max_results', 5))
    if not did:
        raise ValueError('Darktrace Device ID not specified')

    similar_devices = client.list_similar_devices(did=did, max_results=max_results)
    for device in similar_devices:
        if (device['firstSeen']):
            device['firstSeen'] = timestamp_to_datestring(device['firstSeen'])
        if (device['lastSeen']):
            device['lastSeen'] = timestamp_to_datestring(device['lastSeen'])

    readable_output = tableToMarkdown(f'List of similar devices to device:{did}:', similar_devices)
    formatted_output = {'did': int(did), 'devices': similar_devices}

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.SimilarDevices',
        outputs_key_field='did',
        outputs=formatted_output
    )


def get_external_endpoint_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_external_endpoint_details_command: Returns information about a specified external endpoint

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
    endpoint_type = str(args.get('endpoint_type'))
    endpoint_value = str(args.get('endpoint_value'))
    additional_info = str(args.get('additional_info'))
    devices = str(args.get('devices'))
    score = str(args.get('score'))

    endpoint_details = client.get_external_endpoint_details(endpoint_type, endpoint_value, additional_info, devices, score)

    if endpoint_details:
        if endpoint_details['firsttime']:
            endpoint_details['firsttime'] = timestamp_to_datestring(endpoint_details['firsttime'])
        readable_output = tableToMarkdown(f'{endpoint_type.capitalize()}: {endpoint_value} details', endpoint_details)
        formatted_output = endpoint_details
    else:
        readable_output = f'### Did not get any details for {endpoint_type}:{endpoint_value}'
        formatted_output = {}

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.ExternalEndpointDetails',
        outputs=formatted_output
    )


def get_device_connection_info_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_device_connection_info_command: Returns graphing connection information about a specified device

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
    did = args.get('did')
    data_type = args.get('data_type')
    external_domain = args.get('external_domain')
    destination_did = args.get('destination_did')
    show_all_graph_data = args.get('show_all_graph_data', 'false')
    full_device_details = args.get('full_device_details', 'false')
    num_similar_devices = args.get('num_similar_devices')
    device_info_response = client.get_device_connection_info(did, data_type, external_domain, destination_did,
                                                             show_all_graph_data, full_device_details,
                                                             num_similar_devices)
    if device_info_response:
        readable_output = tableToMarkdown(f'Results for device id: {did}', device_info_response)
        formatted_output = device_info_response
    else:
        readable_output = '### No results were found for the given ID'
        formatted_output = {}

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.DeviceConnectionInfo',
        outputs=formatted_output
    )


def get_device_identity_info_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_device_identity_info_command: Returns identifying information about a specified device

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
    max_results = args.get('max_results')
    order_by = args.get('order_by')
    order = args.get('order')
    query = args.get('query')
    device_info_response = client.get_device_identity_info(max_results, order_by, order, query)

    if device_info_response:
        formatted_output = device_info_response
        totalCount = formatted_output['totalCount'] if formatted_output['totalCount'] else 0
        if formatted_output['devices']:
            numResults = len(formatted_output['devices'])
            formatted_output['displayedCount'] = numResults
            for device in formatted_output['devices']:
                if 'firstSeen' in device:
                    device['firstSeen'] = timestamp_to_datestring(device['firstSeen'])
                if 'lastSeen' in device:
                    device['lastSeen'] = timestamp_to_datestring(device['lastSeen'])
            readable_output = tableToMarkdown(f'Results for query: {query} '
                                              f'({numResults} results displayed of {totalCount} which match the query)',
                                              formatted_output['devices'])
        else:
            readable_output = tableToMarkdown(f'Results for query: {query}', formatted_output)
    else:
        readable_output = '### No results were found for the given query'
        formatted_output = {}

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.DeviceIdentityInfo',
        outputs_key_field='devices.did',
        outputs=formatted_output
    )


def get_entity_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_entity_details_command: Returns a time sorted list of connections and events for a device
    or an entity such as a user credential.

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
    max_results = min(50, int(args.get('max_results', 50)))
    offset = int(args.get('offset', 0))
    query_list = argToList(args.get('query'))

    truncated_resp, resp = client.get_entity_details(max_results, offset, query_list)
    if truncated_resp:
        if "device" in truncated_resp[0]:
            readable_output = tableToMarkdown('Results:', truncated_resp[1:])
        else:
            readable_output = tableToMarkdown('Results:', truncated_resp)
        formatted_output = truncated_resp
    else:
        readable_output = 'No details were retrieved for the given parameters'
        formatted_output = {}

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.EntityDetails',
        outputs=formatted_output
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


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """

    # Collect Darktrace URL
    base_url = demisto.params().get('url')

    # Collect API tokens
    public_api_token = demisto.params().get('public_api_token', '')
    private_api_token = demisto.params().get('private_api_token', '')
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
            result = test_module(client, first_fetch_time)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.

            # Convert the argument to an int using helper function or set to MIN_SCORE_TO_FETCH
            min_score = arg_to_int(
                arg=demisto.params().get('min_score'),
                arg_name='min_score',
                required=False
            )
            if not min_score or min_score < MIN_SCORE_TO_FETCH:
                min_score = MIN_SCORE_TO_FETCH

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_alerts = arg_to_int(
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

        elif demisto.command() == 'darktrace-get-breach':
            return_results(get_breach_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-comments':
            return_results(get_comments_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-acknowledge':
            return_results(acknowledge_breach_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-unacknowledge':
            return_results(unacknowledge_breach_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-list-similar-devices':
            return_results(list_similar_devices_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-external-endpoint-details':
            return_results(get_external_endpoint_details_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-device-connection-info':
            return_results(get_device_connection_info_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-device-identity-info':
            return_results(get_device_identity_info_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-entity-details':
            return_results(get_entity_details_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
