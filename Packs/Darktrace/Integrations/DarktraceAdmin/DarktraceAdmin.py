import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import hmac
import json
import traceback
from base64 import b64encode
from datetime import datetime, UTC
from typing import Any
from collections.abc import Mapping

import dateparser
import urllib3

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

# Disable insecure warnings
urllib3.disable_warnings()

"""*****CONSTANTS*****"""
DETAILS_ENDPOINT = '/details'
LIST_SIMILAR_DEVICES_ENDPOINT = '/similardevices'
EXTERNAL_ENDPOINT = '/endpointdetails'
DEVICE_INFO_ENDPOINT = '/deviceinfo'
DEVICE_IDENTITY_ENDPOINT = '/devicesearch'
TAG_ENTITIES_ENDPOINT = '/tags/entities'
INTEL_FEED_ENDPOINT = '/intelfeed'
ADVANCED_SEARCH_ENDPOINT = '/advancedsearch/api/analyze'
STATUS_ENDPOINT = '/status?format=json'

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

    def run_advanced_search_analysis(self, query, metric, operation) -> dict[str, Any]:
        """Returns information from Darktrace advanced search analysis'
        :type query: ``str``
        :param query: Darktrace query string
        :type metric: ``str``
        :param metric: metric to be analyzed
        :type operation: ``str``
        :param operation: type of operation to perform
        :return: list containing advanced search analysis
        :rtype: ``Dict[str, Any]``
        """
        query_url_bytes = b64encode(str(json.dumps(query)).encode())
        query_url = query_url_bytes.decode()
        query_format = f"{ADVANCED_SEARCH_ENDPOINT}/{metric}/{operation}/{query_url}"
        return self.get(query_format)

    def get_device_connection_info(self, **query_params) -> dict[str, Any]:
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
        :return: dictionary containing lists of connection info
        :rtype: ``Dict[str, Any]``
        """
        query_uri = DEVICE_INFO_ENDPOINT
        return self.get(query_uri, query_params)

    def get_external_endpoint_details(self, endpoint_type, endpoint_value, additional_info, devices, score) -> dict[str, Any]:
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
        :rtype: ``Dict[str, Any]``
        """
        query_uri = EXTERNAL_ENDPOINT
        params = {
            endpoint_type: endpoint_value,
            'additionalinfo': additional_info,
            'devices': devices,
            'score': score
        }
        return self.get(query_uri, params)

    def get_similar_devices(self, did, max_results) -> list[dict[str, Any]]:
        """Returns a list of similar devices using '/similardevices'
        :type did: ``str``
        :param did: Device ID of device
        :type max_results: ``str``
        :param max_results: Max # of results to return
        :return: list containing the found Darktrace model breach as a Dict
        :rtype: ``List[Dict[str, Any]]``
        """
        query_uri = LIST_SIMILAR_DEVICES_ENDPOINT
        params = {
            'did': did,
            'count': max_results
        }
        return self.get(query_uri, params)

    def post_to_watched_list(self, addlist, description) -> dict[str, Any]:
        """Returns information from POST endpoints to watched list advanced search analysis
        :type addlist: ``List[str]``
        :param addlist: Darktrace query string
        :type description: ``str``
        :param description: description commit message
        :return: dict containing post result
        :rtype: ``Dict[str, Any]``
        """
        json = {'addlist': addlist}
        if description:
            json['description'] = description
        return self.post(INTEL_FEED_ENDPOINT, json=json)

    def get_tagged_devices(self, tag_name) -> dict[str, Any]:
        """Returns information from devices given a tag as a filter
        :type tag_name: ``str``
        :param tag_name: tag name to query from
        :return: dict containing devices that hold a certain tag
        :rtype: ``List[Dict[str, Any]]``
        """
        params = {"tag": tag_name, "fulldevicedetails": "true"}
        return self.get(TAG_ENTITIES_ENDPOINT, params=params)

    def get_tags_for_device(self, did) -> list[dict[str, Any]]:
        """Returns tags for a certain device
        :type did: ``str``
        :param did: device id
        :return: list containing tag information for a device
        :rtype: ``List[Dict[str, Any]]``
        """
        return self.get(TAG_ENTITIES_ENDPOINT, params={"did": did})

    def post_tag_to_device(self, did, tag_name) -> dict[str, Any]:
        """Returns response from post command
        :type did: ``str``
        :param did: device id
        :type tag_name: ``str``
        :param tag_name: tag name to add to device
        :return: dict containing response from POST request
        :rtype: ``Dict[str, Any]``
        """
        data = {"did": did, "tag": tag_name}
        return self.post(TAG_ENTITIES_ENDPOINT, data)

    def check_status(self) -> dict:
        """Checks a valid api request to the status endpoint
        :return: dict containing status data
        :rtype: ``Dict``
        """
        return self.get(STATUS_ENDPOINT)


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


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])


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


def arg_to_dict(arg, separator=','):
    """Transforms str of an arg into a dict"""
    if not arg:
        return {}
    result = dict(subString.split("=") for subString in (arg).split(separator))
    return result


def check_required_fields(args, *fields):
    """Checks that required fields are found, raises a value error otherwise"""
    for field in fields:
        if field not in args:
            raise ValueError(f'Argument error could not find {field} in {args}')


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client) -> str:
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
        client.check_status()

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def run_advanced_search_analysis_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """run_advanced_search_analysis_command: Runs an advanced search analysis on a specific query and metric and applies an
    operation to returned a list of results.

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
    check_required_fields(args, 'offset', 'initialDate', 'initialTime', 'endDate',
                          'endTime', 'query', 'metric', 'operation', 'offset')
    query = {
        "search": str(args['query']),
        "fields": [],
        "offset": str(args['offset']),
        "timeframe": "custom",
        "graphmode": "count",
        "time": {
            "from": f"{str(args['initialDate'])}T{str(args['initialTime'])}Z",
            "to": f"{str(args['endDate'])}T{str(args['endTime'])}Z",
            "user_interval": "0"
        },
        "mode": "",
        "analyze_field": ""
    }
    adv_search_reponse = client.run_advanced_search_analysis(query, str(args['metric']), str(args['operation']))
    check_required_fields(adv_search_reponse, 'hits')
    hits = adv_search_reponse['hits']
    formatted_output = hits['hits']
    readable_output = tableToMarkdown('Results for Advanced Search Query ', formatted_output, headers=('id', 'count'),
                                      headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.AdvancedSearch',
        outputs=formatted_output
    )


def get_device_connection_info_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    check_required_fields(args, 'deviceId', 'dataType')
    did = args['deviceId']
    show_all_graph_data = args.get('showAllGraphData', 'false')
    full_device_details = args.get('fullDeviceDetails', 'false')
    external_domain = args.get('externalDomain', '')
    destination_device_id = args.get('destinationDeviceId', '')
    num_similar_devices = args.get('numberOfSimilarDevices', 0)
    device_info_response = client.get_device_connection_info(did=did, datatype=args['dataType'],
                                                             externaldomain=external_domain,
                                                             oid=destination_device_id,
                                                             showallgraphdata=show_all_graph_data,
                                                             fulldevicedetails=full_device_details,
                                                             similardevices=num_similar_devices)
    if device_info_response['deviceInfo']:
        readable_output = tableToMarkdown(f'Results for device id: {did}', device_info_response['deviceInfo'])
        formatted_output = device_info_response['deviceInfo']
    else:
        readable_output = '### No results were found for the given ID'
        formatted_output = readable_output

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.DeviceConnectionInfo',
        outputs=formatted_output
    )


def get_external_endpoint_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    check_required_fields(args, 'endpointType', 'endpointValue')
    endpoint_type = str(args['endpointType'])
    endpoint_value = str(args['endpointValue'])

    endpoint_details = client.get_external_endpoint_details(endpoint_type, endpoint_value, str(args['additionalInfo']),
                                                            str(args['devices']), str(args['score']))

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


def get_similar_devices_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """get_similar_devices_command: Returns a list of similar devices to a device specified
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
    check_required_fields(args, 'deviceId')
    did = str(args.get('deviceId', None))
    max_results = str(args.get('maxResults', 5))

    similar_devices = client.get_similar_devices(did=did, max_results=max_results)
    for device in similar_devices:
        if (device['firstSeen']):
            device['firstSeen'] = timestamp_to_datestring(device['firstSeen'])
        if (device['lastSeen']):
            device['lastSeen'] = timestamp_to_datestring(device['lastSeen'])

    readable_output = tableToMarkdown(f'List of similar devices to device:{did}:', similar_devices)
    formatted_output = {'deviceId': int(did), 'devices': similar_devices}

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.Device',
        outputs_key_field='deviceId',
        outputs=formatted_output
    )


def post_to_watched_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """post_to_watched_list_command: Returns a response from posting domains or ips to the watched list domain

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
    check_required_fields(args, 'endpointsToWatch')
    description = str(args.get('description'))
    intel_response = client.post_to_watched_list(addlist=str(args['endpointsToWatch']), description=description)
    readable_data = tableToMarkdown('POST TAG to Device Response', intel_response)
    return CommandResults(
        readable_output=readable_data,
        outputs_prefix='Darktrace.Endpoint',
        outputs=intel_response
    )


def get_tagged_devices_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """get_tagged_devices_command: Gets a list of device information based on a common tag.

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
    check_required_fields(args, 'tagName')
    tag_name = str(args['tagName'])
    device_info_response = client.get_tagged_devices(tag_name=tag_name)
    devices = device_info_response.get('devices')
    output: list = []
    if devices and len(devices):
        for device in devices:
            info: dict[str, Any] = {}
            info['deviceId'] = device['did']
            info['hostname'] = device.get('hostname', 'N/A')
            info['label'] = device.get('devicelabel', 'N/A')
            info['credentials'] = device.get('credentials', 'N/A')
            info['otherTags'] = device.get('tags', 'N/A')
            output.append(info)
    else:
        output.append({'response': 'Unable to locate any devices for the queried tag'})
    readable_output = tableToMarkdown(f'Device Tag Response for device: {tag_name} ', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.Device',
        outputs_key_field='deviceId',
        outputs=output
    )


def get_tags_for_device_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """get_tags_for_device_command: Gets a list of tags for a device

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
    check_required_fields(args, 'deviceId')
    did = str(args['deviceId'])
    device_tags_response = client.get_tags_for_device(did=did)
    output: list = []
    for tag in device_tags_response:
        info: dict[str, Any] = {}
        info['tagId'] = tag['tid']
        info['tagName'] = tag['name']
        info['tagDescription'] = tag['data']['description']
        info['expiry'] = tag['expiry']
        output.append(info)
    readable_output = tableToMarkdown(f'Device Tag Response for device: {did} ', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.Device',
        outputs_key_field='tid',
        outputs=output
    )


def post_tag_to_device_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """post_tag_to_device_command: Posts a tag to a device and returns an action response

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
    check_required_fields(args, 'deviceId', 'tagName')
    tag_name = str(args['tagName'])
    did = str(args['deviceId'])
    post_tag_to_device_response = client.post_tag_to_device(did=did, tag_name=tag_name)
    output: dict[str, Any] = {}
    output['tagId'] = post_tag_to_device_response['tid']
    output['tagName'] = tag_name
    output['deviceId'] = did
    output['response'] = 'Successfully Tagged'
    readable_output = tableToMarkdown('Device Tag Response ', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Darktrace.Device',
        outputs_key_field='deviceId',
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
    public_api_token = demisto.params().get('publicApiKey')
    private_api_token = demisto.params().get('privateApiKey')
    tokens = (public_api_token, private_api_token)

    # Client class inherits from BaseClient, so SSL verification is
    # handled out of the box by it. Pass ``verify_certificate`` to
    # the Client constructor.
    verify_certificate = not demisto.params().get('insecure', False)

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
            return_results(test_module(client))

        elif demisto.command() == 'darktrace-run-advanced-search-analysis':
            return_results(run_advanced_search_analysis_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-device-connection-info':
            return_results(get_device_connection_info_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-external-endpoint-details':
            return_results(get_external_endpoint_details_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-similar-devices':
            return_results(get_similar_devices_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-post-to-watched-list':
            return_results(post_to_watched_list_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-tagged-devices':
            return_results(get_tagged_devices_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-get-tags-for-device':
            return_results(get_tags_for_device_command(client, demisto.args()))

        elif demisto.command() == 'darktrace-post-tag-to-device':
            return_results(post_tag_to_device_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
