import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
''' IMPORTS '''

import requests
import traceback
from json.decoder import JSONDecodeError
from typing import Dict, Any, Tuple, cast

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # noqa # pylint: disable=no-member


''' CONSTANTS '''
SOCRADAR_API_ENDPOINT = 'https://platform.socradar.com/api'
SOCRADAR_SEVERITIES = ['Unknown', 'Info', 'Low', 'Medium', 'High']
EXCLUDED_INCIDENT_FIELDS = ('extra_info', 'alarm_notification_texts')
MAX_INCIDENTS_TO_FETCH = 50

MESSAGES: Dict[str, str] = {
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'AUTHORIZATION_ERROR': 'Authorization Error: make sure API Key is correctly set.',
    'RATE_LIMIT_EXCEED_ERROR': 'Rate limit has been exceeded. Please make sure your your API key\'s rate limit is adequate.',
}

''' HELPER FUNCTIONS '''


def parse_int_or_raise(str_to_parse: Any, error_msg=None) -> int:
    """Parse a string to integer. Raise ValueError exception if fails with given error_msg
    """
    try:
        res = int(str_to_parse)
    except (TypeError, ValueError):
        if not error_msg:
            error_msg = f"Error while parsing integer! Provided string: {str_to_parse}"
        raise ValueError(error_msg)
    return res


def convert_to_demisto_severity(severity: str) -> Union[int, float]:
    """Maps SOCRadar severity to Cortex XSOAR severity

    Converts the SOCRadar alert severity level ('INFO', 'LOW', 'MEDIUM', 'HIGH') to Cortex XSOAR incident severity
    (1 to 4) for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the SOCRadar API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    return {
        'INFO': IncidentSeverity.INFO,
        'LOW': IncidentSeverity.LOW,
        'MEDIUM': IncidentSeverity.MEDIUM,
        'HIGH': IncidentSeverity.HIGH,
        'UNKNOWN': IncidentSeverity.UNKNOWN
    }[severity]


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, api_key, socradar_company_id, verify, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.socradar_company_id = socradar_company_id

    def check_auth(self):
        suffix = f'/company/{self.socradar_company_id}/incidents/check/auth'
        api_params = {'key': self.api_key}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params,
                                      error_handler=self.handle_error_response)

        return response

    def search_incidents(self, resolution_status: Optional[str], fp_status: Optional[str],
                         severity: Optional[List[str]], incident_main_type: Optional[str],
                         incident_sub_type: Optional[str], max_results: Optional[int],
                         start_date: Optional[int]):
        """Searches for SOCRadar incidents using the '/incidents/latest' API endpoint

        All the parameters are passed directly to the API as HTTP GET parameters in the request

        :type resolution_status: ``Optional[str]``
        :param resolution_status: Resolution status of the incident to search for. Options are: 'All', 'Resolved', 'Not Resolved'

        :type fp_status: ``Optional[str]``
        :param fp_status: False Positive status of the incident to search for. Options are: 'All', 'FP', 'Not FP'

        :type severity: ``Optional[List[str]]``
        :param severity:
            severity of the alert to search for.
            Options are: "Low", "Medium", "High", "Critical"

        :type incident_main_type: ``Optional[str]``
        :param incident_main_type: main type of incidents to search for. There is no list of predefined types.

        :type incident_sub_type: ``Optional[str]``
        :param incident_sub_type: sub type of incidents to search for. There is no list of predefined types.

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_date: ``Optional[int]``
        :param start_date.
        : start timestamp (epoch in seconds) for the alert search
        """

        api_params: Dict[str, Any] = {'key': self.api_key}

        if resolution_status and resolution_status.lower() != 'all':
            api_params['is_resolved'] = True if resolution_status.lower() == 'resolved' else False

        if fp_status and fp_status.lower() != 'all':
            api_params['is_false_positive'] = True if fp_status.lower() == 'fp' else False

        if incident_main_type:
            api_params['incident_main_type'] = incident_main_type

        if incident_sub_type:
            api_params['incident_sub_type'] = incident_sub_type

        if severity:
            api_params['severity'] = ','.join(severity)

        if max_results:
            api_params['limit'] = max_results

        if start_date:
            api_params['start_date'] = start_date

        suffix = f'/company/{self.socradar_company_id}/incidents/v2'
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params, timeout=60,
                                      error_handler=self.handle_error_response)
        if not response.get('is_success'):
            message = f"Error while getting API response. SOCRadar API Response: {response.get('message', '')}"
            raise DemistoException(message=message)
        return response.get('data') if response else []

    def mark_incident_as_false_positive(self, incident_id: int, comments: Optional[str]):
        """Sends a request that marks incident as false positive in SOCRadar platform
        using '/company/{company_id}/incidents/fp'. All the parameters are passed directly to the API as
        HTTP GET parameters in the request

        :type incident_id: ``int``
        :param incident_id: SOCRadar incident ID of particular incident to that will be used to mark it as false positive.

        :type comments: ``Optional[str]``
        :param comments: Possible comments of the mark as false positive action which will be sent to SOCRadar.
        """

        api_params: Dict[str, str] = {'key': self.api_key}
        json_data = {'alarm_ids': [incident_id], 'comments': comments}

        suffix = f'/company/{self.socradar_company_id}/incidents/fp'
        response = self._http_request(method='POST', url_suffix=suffix, params=api_params, json_data=json_data,
                                      timeout=60, error_handler=self.handle_error_response)
        return response

    def mark_incident_as_resolved(self, incident_id: int, comments: Optional[str]):
        """Sends a request that marks incident as resolved in SOCRadar platform
        using '/company/{company_id}/incidents/resolve'. All the parameters are passed directly to the API as
        HTTP GET parameters in the request

        :type incident_id: ``int``
        :param incident_id: SOCRadar incident ID of particular incident to that will be used to mark it as resolved.

        :type comments: ``Optional[str]``
        :param comments: Possible comments of the mark as resolved action which will be sent to SOCRadar.
        """

        api_params: Dict[str, str] = {'key': self.api_key}
        json_data: Dict[str, Any] = {'alarm_ids': [incident_id], 'comments': comments}

        suffix = f'/company/{self.socradar_company_id}/incidents/resolve'
        response = self._http_request(method='POST', url_suffix=suffix, params=api_params, json_data=json_data,
                                      timeout=60, error_handler=self.handle_error_response)
        return response

    @staticmethod
    def handle_error_response(response) -> None:
        """Handles API response to display descriptive error messages based on status code

        :param response: SOCRadar API response.
        :return: DemistoException for particular error code.
        """

        error_reason = ''
        try:
            json_resp = json.loads(response.text)
            error_reason = json_resp.get('error') or json_resp.get('message')
        except JSONDecodeError:
            pass

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            401: MESSAGES['AUTHORIZATION_ERROR'],
            404: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            429: MESSAGES['RATE_LIMIT_EXCEED_ERROR']
        }

        if response.status_code in status_code_messages.keys():
            demisto.debug(f'Response Code: {response.status_code}, Reason: {status_code_messages[response.status_code]}')
            raise DemistoException(status_code_messages[response.status_code])
        else:
            raise DemistoException(response.raise_for_status())


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.check_auth()
    return "ok"


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], resolution_status: Optional[str], fp_status: Optional[str],
                    severity: List[str], incident_main_type: Optional[str], incident_sub_type: Optional[str]
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """
    :type client: ``Client``
    :param client: SOCRadar client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains the timestamp that tells
         when to start fetching incidents

    :type resolution_status: ``Optional[str]``
    :param resolution_status:
        Resolution status of the incident to search for. Options are: 'All', 'Resolved', 'Not Resolved'

    :type fp_status: ``Optional[str]``
    :param fp_status:
        False positive status of the incident to search for. Options are: 'All', 'FP', 'Not FP'

    :type severity: ``List[str]``
    :param severity:
        severity level(s) of the incidents to fetch.
        Options are: "Info", "Medium", "Low", "High"

    :type incident_main_type: ``Optional[str]``
    :param incident_main_type: Main type of incidents to search for. There is no list of predefined types

    :type incident_sub_type: ``Optional[str]``
    :param incident_sub_type: Sub type of incidents to search for. There is no list of predefined types

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch')
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # Check if severity contains allowed values, use all if default
    if severity:
        if not all(s in SOCRADAR_SEVERITIES for s in severity):
            raise ValueError(
                f'severity must be a comma-separated value '
                f'with the following options: {",".join(SOCRADAR_SEVERITIES)}')
    alerts = client.search_incidents(
        incident_main_type=incident_main_type,
        incident_sub_type=incident_sub_type,
        resolution_status=resolution_status,
        fp_status=fp_status,
        max_results=max_results,
        start_date=last_fetch,
        severity=severity
    )

    for alert in alerts:
        insert_date_str = alert.get('insert_date', '').split('.')[0]
        insert_date = datetime.strptime(insert_date_str, '%Y-%m-%dT%H:%M:%S')
        insert_date_utc = insert_date.replace(tzinfo=timezone.utc)
        incident_created_time = int(insert_date_utc.timestamp())
        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue

        incident_content = alert.get('alarm_notification_texts', {}).get('alarm_text', '')
        alert = {
            **{key: value for key, value in alert.items() if key not in EXCLUDED_INCIDENT_FIELDS},
            'alarm_notification_texts': {'alarm_title': alert.get('alarm_notification_texts', {}).get('alarm_title', '')}
        }

        incident_name = f"{alert.get('alarm_notification_texts', {}).get('alarm_title', '')} - [#{alert.get('id', '')}]"

        alert_assets = ' || '.join(alert.get('alarm_assets', []))
        alert_related_assets = ''
        for related_asset_dict in alert.get('alarm_related_assets', []):
            related_asset_key, related_asset_value_list = related_asset_dict.get('key'), related_asset_dict.get('value', [])
            related_asset_value_list: List[str] = list(filter(None, related_asset_value_list))
            if related_asset_key and related_asset_value_list:
                related_asset_value_list = [str(value) for value in related_asset_value_list]
                alert_related_assets += f"{related_asset_key}: {' || '.join(related_asset_value_list)}\n"

        alert_related_entities = ''
        for related_entity_dict in alert.get('alarm_related_entities', []):
            related_entity_key, related_entity_value_list = related_entity_dict.get('key'), related_entity_dict.get('value', [])
            related_entity_value_list: List[str] = list(filter(None, related_entity_value_list))
            if related_entity_key and related_entity_value_list:
                related_entity_value_list = [str(value) for value in related_entity_value_list]
                alert_related_entities += f"{related_entity_key}: {' || '.join(related_entity_value_list)}\n"

        incident_link = f"https://platform.socradar.com/company/{client.socradar_company_id}/incidents/{alert.get('id', '')}"

        incident = {
            'name': incident_name,
            'occurred': timestamp_to_datestring(incident_created_time * 1000, is_utc=True),
            'rawJSON': json.dumps(alert),
            'severity': convert_to_demisto_severity(alert.get('alarm_risk_level', 'UNKNOWN')),
            'CustomFields': {
                'socradarincidentassets': alert_assets,
                'socradarmitigation': alert.get('alarm_mitigation', ''),
                'socradarrelatedassets': alert_related_assets,
                'socradarrelatedentities': alert_related_entities,
                'incidentlink': incident_link,
                'socradarincidentcontent': incident_content,
            }
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def mark_incident_as_fp_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Sends a request that marks incident as false positive in SOCRadar platform.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, str]
    :param args: contains all arguments for mark_incident_as_fp_command

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    incident_id = parse_int_or_raise(args.get('socradar_incident_id', ''))
    comments = args.get('comments', '')
    raw_response = client.mark_incident_as_false_positive(
        incident_id=incident_id,
        comments=comments
    )
    if raw_response.get('is_success'):
        message = f"SOCRadar API Response: {raw_response.get('message', '')}"
    else:
        message = f"Error while getting API response. SOCRadar API Response: {raw_response.get('message', '')}"
        raise DemistoException(message=message)

    return CommandResults(
        readable_output=message,
        raw_response=raw_response
    )


def mark_incident_as_resolved_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Sends a request that marks incident as resolved in SOCRadar platform.

    :param client: client to use
    :type client: ``Client``

    :type args: Dict[str, str]
    :param args: contains all arguments for mark_incident_as_resolved_command

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    incident_id = parse_int_or_raise(args.get('socradar_incident_id', ''))
    comments = args.get('comments', '')
    raw_response = client.mark_incident_as_resolved(
        incident_id=incident_id,
        comments=comments
    )
    if raw_response.get('is_success'):
        message = f"SOCRadar API Response: {raw_response.get('message', '')}"
    else:
        message = f"Error while getting API response. SOCRadar API Response: {raw_response.get('message', '')}"
        raise DemistoException(message=message)

    return CommandResults(
        readable_output=message,
        raw_response=raw_response
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')
    socradar_company_id = demisto.params().get('socradar_company_id')

    base_url = SOCRADAR_API_ENDPOINT
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '40 days').strip(),
        arg_name='First fetch time',
        required=True
    )

    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else 0
    assert isinstance(first_fetch_timestamp, int)

    verify_certificate = argToBoolean(demisto.params().get('insecure', False))
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            socradar_company_id=socradar_company_id,
            verify=verify_certificate,
            proxy=proxy)
        command = demisto.command()

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            resolution_status = demisto.params().get('resolution_status')
            fp_status = demisto.params().get('fp_status')
            incident_main_type = demisto.params().get('incident_main_type')
            incident_sub_type = demisto.params().get('incident_sub_type')
            severity = demisto.params().get('severity')

            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                resolution_status=resolution_status,
                fp_status=fp_status,
                severity=severity,
                incident_main_type=incident_main_type,
                incident_sub_type=incident_sub_type,
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'socradar-mark-incident-fp':
            return_results(
                mark_incident_as_fp_command(
                    client=client,
                    args=demisto.args()
                )
            )
        elif command == 'socradar-mark-incident-resolved':
            return_results(
                mark_incident_as_resolved_command(
                    client=client,
                    args=demisto.args()
                )
            )

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
