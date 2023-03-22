# pylint: disable=unsubscriptable-object
''' IMPORTS '''

import copy
from CommonServerPython import *
from requests import Response
from contextlib import closing
import json
import dateparser
from typing import Dict, List, Optional, Tuple, Iterable
''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SEVERITIES = {'low': 1, 'medium': 2, 'high': 3, 'very_high': 4}
CSV_FIELDS_TO_EXTRACT = ['Username', 'Password']


class Client(BaseClient):
    """
    API Client to communicate with Cyberint API endpoints.
    """

    def __init__(self, base_url: str, access_token: str, verify_ssl: bool,
                 proxy: bool):
        """
        Client for CyberInt RESTful API.

        Args:
            base_url (str): URL to access when getting alerts.
            access_token (str): Access token for authentication.
            verify_ssl (bool): specifies whether to verify the SSL certificate or not.
            proxy (bool): specifies if to use XSOAR proxy settings.
        """
        self._cookies = {'access_token': access_token}
        super().__init__(base_url=base_url, verify=verify_ssl, proxy=proxy)

    def list_alerts(self, page: Optional[str], page_size: Optional[int],
                    created_date_from: Optional[str],
                    created_date_to: Optional[str],
                    modification_date_from: Optional[str],
                    modification_date_to: Optional[str],
                    environments: Optional[List[str]],
                    statuses: Optional[List[str]],
                    severities: Optional[List[str]],
                    types: Optional[List[str]]) -> Dict:
        """
        Retrieve a list of alerts according to parameters.

        Args:
            page (str): Index of page to return.
            page_size (int): Size of the page to return.
            created_date_from (str): Minimal ISO-Formatted creation date.
            created_date_to (str): Maximal ISO-Formatted creation date.
            modification_date_from (str): Minimal ISO-Formatted modification date.
            modification_date_to (str): Maximal ISO-Formatted modification date.
            environments (list(str)): Environments in which the alerts were created.
            statuses (list(str)): Alerts statuses.
            severities (list(str)): Alerts severities.
            types (list(str)): Alerts type.

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {
            'page': page,
            'size': page_size,
            'include_csv_attachments_as_json_content': True,
            'filters': {
                'created_date': {
                    'from': created_date_from,
                    'to': created_date_to
                },
                'modification_date': {
                    'from': modification_date_from,
                    'to': modification_date_to
                },
                'environments': environments,
                'status': statuses,
                'severity': severities,
                'type': types
            }
        }
        body = remove_empty_elements(body)
        response = self._http_request(method='POST',
                                      json_data=body,
                                      cookies=self._cookies,
                                      url_suffix='api/v1/alerts')
        return response

    def update_alerts(self, alerts: List[str], status: Optional[str],
                      closure_reason: Optional[str]) -> Dict:
        """
        Update the status of one or more alerts

        Args:
            alerts (list(str)): Reference IDs for the alert(s)
            status (str): Desired status to update for the alert(s)
            closure_reason (str): Reason for updating the alerts status to closed.

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {
            'alert_ref_ids': alerts,
            'data': {
                'status': status,
                'closure_reason': closure_reason
            }
        }
        body = remove_empty_elements(body)
        response = self._http_request(method='PUT',
                                      json_data=body,
                                      cookies=self._cookies,
                                      url_suffix='api/v1/alerts/status')
        return response

    def get_csv_file(self,
                     alert_id: str,
                     attachment_id: str,
                     delimiter: bytes = b'\r\n') -> Iterable[str]:
        """
        Stream a CSV file attachment in order to extract data out of it.

        Args:
            alert_id (str): ID of the alert the CSV belongs to.
            attachment_id (str): ID of the specific CSV file.
            delimiter (str): Delimiter for the CSV file.

        Returns:
            row (generator(str)): Generator containing each line of the CSV.
        """
        url_suffix = f'api/v1/alerts/{alert_id}/attachments/{attachment_id}'
        with closing(
                self._http_request(method='GET',
                                   url_suffix=url_suffix,
                                   cookies=self._cookies,
                                   resp_type='all',
                                   stream=True)) as r:
            for line in r.iter_lines(delimiter=delimiter):
                yield line.decode('utf-8').strip('"')

    def get_alert_attachment(self, alert_ref_id: str,
                             attachment_id: str) -> Response:
        """
        Retrieve attachment by alert reference ID and attachment ID.

        Args:
            alert_ref_id (str): Reference ID of the alert.
            attachment_id (str): The ID of the attachment.

        Returns:
            Response: API response from Cyberint.
        """

        url_suffix = f'api/v1/alerts/{alert_ref_id}/attachments/{attachment_id}'
        return self._http_request(method='GET',
                                  cookies=self._cookies,
                                  url_suffix=url_suffix,
                                  resp_type='response')

    def get_analysis_report(self, alert_ref_id: str) -> Response:
        """
        Retrieve analysis report by alert reference ID.

        Args:
            alert_ref_id (str): Reference ID of the alert.

        Returns:
            Response: API response from Cyberint.

        """
        url_suffix = f'api/v1/alerts/{alert_ref_id}/analysis_report'
        return self._http_request(method='GET',
                                  cookies=self._cookies,
                                  url_suffix=url_suffix,
                                  resp_type='response')


def test_module(client: Client):
    """
    Test the connection to the API by sending a normal request.

    Args:
        client (Client): Cyberint API  client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        result = client.list_alerts(*([None] * 10))
        if result:
            return 'ok'
    except DemistoException as exception:
        if 'Invalid token or token expired' in str(exception):
            error_message = 'Error verifying access token and / or environment, make sure the ' \
                            'configuration parameters are correct.'
        else:
            error_message = str(exception)
        raise DemistoException(error_message)


def verify_input_date_format(date: Optional[str]) -> Optional[str]:
    """
    Make sure a date entered by the user is in the correct string format (with a Z at the end).

    Args:
        date (str): Date string given by the user. Can be None.

    Returns:
        str: Fixed date in the same format as the one needed by the API.
    """
    if date and not date.endswith('Z'):
        date += 'Z'
    return date


def set_date_pair(
        start_date_arg: Optional[str], end_date_arg: Optional[str],
        date_range_arg: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Calculate the date range to send to the API based on the arguments from the user.

    Args:
        start_date_arg (str): Optional start_date from the user.
        end_date_arg (str): Optional end_date from the user.
        date_range_arg (str): Optional date range from the user.

    Returns:
        start_date (str): Start date to send to the API.
        end_date (str): End date to send to the API.
    """
    if date_range_arg:
        start_date, end_date = parse_date_range(date_range=date_range_arg,
                                                date_format=DATE_FORMAT,
                                                utc=False)
        return start_date, end_date
    min_date = datetime.fromisocalendar(2020, 2, 1)
    start_date_arg = verify_input_date_format(start_date_arg)
    end_date_arg = verify_input_date_format(end_date_arg)
    if start_date_arg and not end_date_arg:
        end_date_arg = datetime.strftime(datetime.now(), DATE_FORMAT)
    elif end_date_arg and not start_date_arg:
        start_date_arg = datetime.strftime(min_date, DATE_FORMAT)
    return start_date_arg, end_date_arg


def extract_data_from_csv_stream(client: Client,
                                 alert_id: str,
                                 attachment_id: str,
                                 delimiter: bytes = b'\r\n') -> List[dict]:
    """
    Call the attachment download API and parse required fields.

    Args:
        client (Client): Cyberint API client.
        alert_id (str): ID of the alert the attachment belongs to.
        attachment_id (str): ID of the attachment itself.
        delimiter (bytes): Delimeter for the CSV file.

    Returns:
        list(dict): List of all the data found using the wanted fields.
    """
    first_line = True
    field_indexes = {}  # {wanted_field_name: wanted_field_index...}
    information_found = []
    for csv_line in client.get_csv_file(alert_id, attachment_id, delimiter):
        csv_line_separated = csv_line.split(',')
        if first_line:
            for field in CSV_FIELDS_TO_EXTRACT:
                try:
                    field_indexes[field] = csv_line_separated.index(field)
                except ValueError:
                    pass
            first_line = False
        else:
            try:
                extracted_field_data = {
                    field_name.lower(): csv_line_separated[field_index]
                    for field_name, field_index in field_indexes.items()
                }
                if extracted_field_data:
                    information_found.append(extracted_field_data)
            except IndexError:
                pass
    return information_found


def cyberint_alerts_fetch_command(client: Client,
                                  args: dict) -> CommandResults:
    """
    List alerts on cyberint according to parameters.

    Args:
        client (Client): Cyberint API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    created_date_from, created_date_to = set_date_pair(
        args.get('created_date_from', None), args.get('created_date_to', None),
        args.get('created_date_range', None))
    modify_date_from, modify_date_to = set_date_pair(
        args.get('modification_date_from', None),
        args.get('modification_date_to', None),
        args.get('modification_date_range', None))
    if int(args.get('page_size', 10)) < 10 or int(args.get('page_size',
                                                           10)) > 100:
        raise DemistoException('Page size must be between 10 and 100.')
    result = client.list_alerts(args.get('page'), args.get('page_size'),
                                created_date_from, created_date_to,
                                modify_date_from, modify_date_to,
                                argToList(args.get('environments')),
                                argToList(args.get('statuses')),
                                argToList(args.get('severities')),
                                argToList(args.get('types')))
    alerts = result.get('alerts', [])
    outputs = []
    for alert in alerts:
        alert_csv_id = alert.get('alert_data', {}).get('csv', {}).get('id', '')
        if alert_csv_id:
            alert['csv_data'] = {
                'csv_id': alert_csv_id,
                'name': dict_safe_get(alert, ['alert_data', 'csv', 'name']),
                'content': dict_safe_get(alert,
                                         ['alert_data', 'csv', 'content'])
            }
            extracted_csv_data = extract_data_from_csv_stream(
                client, alert.get('ref_id', ''), alert_csv_id)
            alert['alert_data']['csv'] = extracted_csv_data
        outputs.append(alert)
    total_alerts = result.get('total')
    table_headers = [
        'ref_id', 'title', 'status', 'severity', 'created_date', 'type',
        'environment'
    ]
    readable_output = f'Total alerts: {total_alerts}\nCurrent page: {args.get("page", 1)}\n'
    readable_output += tableToMarkdown(name='CyberInt alerts:',
                                       t=outputs,
                                       headers=table_headers,
                                       removeNull=True)
    return CommandResults(outputs_key_field='ref_id',
                          outputs_prefix='Cyberint.Alert',
                          readable_output=readable_output,
                          raw_response=result,
                          outputs=outputs)


def cyberint_alerts_status_update(client: Client,
                                  args: dict) -> CommandResults:
    """
        Update the status of one or more alerts

        Args:
        client (Client): Cyberint API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_ids = argToList(args.get('alert_ref_ids'))
    status = args.get('status')
    closure_reason = args.get('closure_reason')
    if status == 'closed' and not closure_reason:
        raise DemistoException(
            'You must supply a closure reason when closing an alert.')
    response = client.update_alerts(alert_ids, status, closure_reason)
    table_headers = ['ref_id', 'status', 'closure_reason']
    outputs = []
    for alert_id in alert_ids:
        outputs.append({
            'ref_id': alert_id,
            'status': status,
            'closure_reason': closure_reason
        })

    readable_output = tableToMarkdown(
        name='CyberInt alerts updated information:',
        t=outputs,
        headers=table_headers,
        removeNull=True)
    return CommandResults(outputs_key_field='ref_id',
                          outputs_prefix='Cyberint.Alert',
                          readable_output=readable_output,
                          raw_response=response,
                          outputs=outputs)


def cyberint_alerts_get_attachment_command(client: Client, alert_ref_id: str,
                                           attachment_id: str,
                                           attachment_name: str) -> Dict:
    """
    Retrieve attachment by alert reference ID and attachment internal ID.
    Attachments includes: CSV files , Screenshots, and alert attachments files.

    Args:
        client (Client): Cyberint API client.
        alert_ref_id (str): Reference ID of the alert.
        attachment_id (str): The ID of the alert attachment.
        attachment_name (str): The file name of the alert attachment.

    Returns:
        Dict: Alert attachment file result.

    """

    raw_response = client.get_alert_attachment(alert_ref_id, attachment_id)

    return fileResult(filename=attachment_name, data=raw_response.content)


def cyberint_alerts_get_analysis_report_command(client: Client,
                                                alert_ref_id: str,
                                                report_name: str) -> Dict:
    """
    Retrieve expert analysis report by alert reference ID and report name.

    Args:
        client (Client): Cyberint API client.
        alert_ref_id (str): Reference ID of the alert.
        report_name (str): The name of the alert expert analysis report.

    Returns:
        Dict: Alert attachment file result.

    """
    raw_response = client.get_analysis_report(alert_ref_id)
    return fileResult(filename=report_name, data=raw_response.content)


def get_attachment_name(attachment_name: str) -> str:
    """
    Retrieve attachment name or error string if none is provided.

    Args:
        attachment_name (str): Attachment name to retrieve.

    Returns:
        str: The attachment file name or 'xsoar_untitled_attachment' by default.

    """
    if attachment_name is None or attachment_name == "":
        return "xsoar_untitled_attachment"
    return attachment_name


def create_fetch_incident_attachment(raw_response: Response,
                                     attachment_file_name: str) -> dict:
    """
    Create suitable attachment information dictionary object.
    This dictionary object will be used as an entry in the fetch-incidents attachments list.
    For each attachment file, it is necessary to save the relevant fields that return from this function,
    in order to represent the attachment in the layout.

    Args:
        raw_response (Response): Cyberint API response from retrieving the alert attachment.
        attachment_file_name (str): The name of the attachment.

    Returns:
        dict: Attachment file information.Includes - path, name, and showMediaFile.
    """

    attachment_name = get_attachment_name(attachment_file_name)
    file_result = fileResult(filename=attachment_name,
                             data=raw_response.content)

    return {
        "path": file_result["FileID"],
        "name": attachment_name,
        "showMediaFile": True
    }


def get_alert_attachments(client: Client, attachment_list: List,
                          attachment_type: str, alert_id: str) -> List:
    """
    Retrieve all alert attachments files - Attachments, CSV, Screenshot, and Analysis report.
    For each attachment, we save and return the relevant fields in order to represent the attachment in the layout.

    Args:
        client (Client): Cyberint API client.
        attachment_list (List): Alert attachments list. Each element in the list contains id, mimetype and name fields.
        attachment_type (str): The type of the attachment. Can be 'attachment' or 'analysis_report'.
        alert_id (str): The ID of the alert.

    Returns:
        (List): incident attachments details - contains the file details of the attachment.

    """
    incident_attachments = []

    for attachment in attachment_list:
        if attachment:
            if attachment_type == 'analysis_report':
                raw_response = client.get_analysis_report(alert_id)
                incidents_attachment = create_fetch_incident_attachment(
                    raw_response, attachment.get('name', None))
            else:
                raw_response = client.get_alert_attachment(
                    alert_id, attachment.get('id', None))
                incidents_attachment = create_fetch_incident_attachment(
                    raw_response, attachment.get('name', None))

            if incidents_attachment:
                incident_attachments.append(incidents_attachment)

    return incident_attachments


def fetch_incidents(
        client: Client, last_run: Dict[str, int], first_fetch_time: str,
        fetch_severity: Optional[List[str]], fetch_status: Optional[List[str]],
        fetch_type: Optional[List[str]],
        fetch_environment: Optional[List[str]], max_fetch: Optional[int],
        duplicate_alert: bool) -> Tuple[Dict[str, int], List[dict]]:
    """
    Fetch incidents (alerts) each minute (by default).
    Args:
        client (Client): Cyberint Client.
        last_run (dict): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp).
        first_fetch_time (dict): Dict with first fetch time in str (ex: 3 days ago).
        fetch_severity (list(str)): Severities to fetch.
        fetch_status (list(str)): Statuses to fetch.
        fetch_type (list(str)): Types to fetch.
        fetch_environment (list(str)): Environments to fetch.
        max_fetch (int): Max number of alerts to fetch.
    Returns:
        Tuple of next_run (seconds timestamp) and the incidents list
    """
    #  Start by setting the time to fetch from.
    last_fetch_timestamp = last_run.get('last_fetch', None)
    if last_fetch_timestamp:
        last_fetch_date = datetime.fromtimestamp(last_fetch_timestamp / 1000)
        last_fetch = last_fetch_date
    else:
        first_fetch_date = dateparser.parse(first_fetch_time)
        last_fetch = first_fetch_date  # type: ignore
    incidents = []
    next_run = last_fetch
    #  Send the API request to fetch the alerts.
    alerts = client.list_alerts('1', max_fetch,
                                datetime.strftime(last_fetch, DATE_FORMAT),
                                datetime.strftime(datetime.now(), DATE_FORMAT),
                                None, None, fetch_environment, fetch_status,
                                fetch_severity, fetch_type)

    for alert_object in alerts.get('alerts', []):
        alert = dict(alert_object)
        #  Create the XS0AR incident.
        alert_created_time = datetime.strptime(
            alert.get('created_date'), '%Y-%m-%dT%H:%M:%S')  # type: ignore

        alert_id = alert.get('ref_id')
        alert_title = alert.get('title')
        attachments = []
        incident_attachments = []

        attachments_keys = {
            'attachment': [["attachments"], ["alert_data", "screenshot"],
                           ["alert_data", "csv"]],
            'analysis_report': [['analysis_report']]
        }
        for attachment_type, attachments_path in attachments_keys.items():
            for path in attachments_path:
                current_attachments = dict_safe_get(alert,
                                                    path,
                                                    default_return_value=[])
                attachment_list = current_attachments if isinstance(
                    current_attachments, list) else [current_attachments]
                # Retrieve alert Incident attachments files - Attachments, CSV, Screenshot, and Analysis report.
                current_incident_attachments = get_alert_attachments(
                    client, attachment_list, attachment_type,
                    alert_id)  # type: ignore

                incident_attachments.extend(current_incident_attachments)
                for tmp_attachment in attachment_list:
                    if tmp_attachment:
                        attachments.append(tmp_attachment)

        alert["attachments"] = attachments
        alert_data = dict_safe_get(alert, ['alert_data', 'csv'], {})
        incident_csv_records = alert_data.get('content', [])

        alert_csv_id = dict_safe_get(alert, ['alert_data', 'csv', 'id'])

        if alert_csv_id:
            extracted_csv_data = extract_data_from_csv_stream(
                client,
                alert_id,  # type: ignore
                alert_csv_id)
            alert['alert_data']['csv'] = extracted_csv_data

        # add alert_name key to alert response
        alert_name = f'Cyberint alert {alert_id}: {alert_title}'
        alert.update({'alert_name': alert_name})

        incident = {
            'name': alert_name,
            'occurred': datetime.strftime(alert_created_time, DATE_FORMAT),
            'rawJSON': json.dumps(alert),
            'severity': SEVERITIES.get(alert.get('severity', 'low')),
            'attachment': incident_attachments,
        }

        if duplicate_alert and incident_csv_records:
            for index, incident_csv_record in enumerate(incident_csv_records):
                alert_data.update({'content': incident_csv_record})
                alert.update({'attachments': alert_data})

                alert_name = f'Cyberint alert {alert_id} ({index+1}): {alert_title}'
                alert.update({'alert_name': alert_name})

                incident.update({
                    'name': alert_name,
                    'rawJSON': json.dumps(alert)
                })
                incidents.append(copy.deepcopy(incident))
        else:
            incidents.append(incident)

    if incidents:
        #  Update the time for the next fetch so that there won't be duplicates.
        last_incident_time = incidents[0].get('occurred', '')
        next_run = datetime.strptime(str(last_incident_time), DATE_FORMAT)
    next_run += timedelta(seconds=1)
    next_run_timestamp = int(datetime.timestamp(next_run) * 1000)
    return {'last_fetch': next_run_timestamp}, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    command = demisto.command()
    access_token = params.get('access_token')
    environment = params.get('environment')

    verify_certificate = not params.get('insecure', False)
    first_fetch_time = params.get('first_fetch', '3 days').strip()
    proxy = params.get('proxy', False)
    base_url = f'https://{environment}.cyberint.io/alert/'
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(base_url=base_url,
                        verify_ssl=verify_certificate,
                        access_token=access_token,
                        proxy=proxy)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            fetch_environment = argToList(params.get('fetch_environment', ''))
            fetch_status = params.get('fetch_status', [])
            fetch_type = params.get('fetch_type', [])
            fetch_severity = params.get('fetch_severity', [])
            max_fetch = int(params.get('max_fetch', '50'))
            duplicate_alert = params.get('duplicate_alert', False)
            next_run, incidents = fetch_incidents(client, demisto.getLastRun(),
                                                  first_fetch_time,
                                                  fetch_severity, fetch_status,
                                                  fetch_type,
                                                  fetch_environment, max_fetch,
                                                  duplicate_alert)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'cyberint-alerts-fetch':
            return_results(
                cyberint_alerts_fetch_command(client, demisto.args()))

        elif command == 'cyberint-alerts-status-update':
            return_results(
                cyberint_alerts_status_update(client, demisto.args()))

        elif command == 'cyberint-alerts-get-attachment':
            return_results(
                cyberint_alerts_get_attachment_command(client,
                                                       **demisto.args()))

        elif command == 'cyberint-alerts-analysis-report':
            return_results(
                cyberint_alerts_get_analysis_report_command(
                    client, **demisto.args()))
    except Exception as e:

        if 'Invalid token or token expired' in str(e):
            error_message = 'Error verifying access token and / or environment, make sure the ' \
                            'configuration parameters are correct.'
        elif 'datetime' in str(e).lower():
            error_message = 'Invalid time specified, ' \
                            'make sure the arguments are correctly formatted and are not ' \
                            'earlier than 2020 or later than the current time.'
        elif 'Unauthorized alerts requested' in str(e):
            error_message = 'Some of the alerts selected to update are either blocked or not found.'
        else:
            error_message = f'Failed to execute {command} command. Error: {str(e)}'
        return_error(error_message)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
