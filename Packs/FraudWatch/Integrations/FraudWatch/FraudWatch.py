import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Tuple

import pytz
import urllib3
from requests import Response


# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
MINIMUM_POSITIVE_VALUE = 1
MAX_PAGE_SIZE_VALUE = 200
DEFAULT_PAGE_SIZE_VALUE = 50
MAX_PAGE_SIZE_BRANDS = 100
MINIMUM_PAGE_SIZE_BRANDS = 20
DEFAULT_URL = 'https://www.phishportal.com/'

FRAUD_WATCH_DATE_FORMAT = '%Y-%m-%d'

INCIDENT_LIST_MARKDOWN_HEADERS = ['identifier', 'reference_id', 'url', 'status', 'type', 'brand', 'client',
                                  'content_ip', 'host', 'host_country', 'host_timezone', 'created_by', 'discovered_by',
                                  'current_duration', 'active_duration', 'date_opened', 'date_closed',
                                  'additional_urls', 'link']

UTC_TIMEZONE = pytz.timezone('utc')
''' CLIENT CLASS '''


class Client(BaseClient):
    URL_ENCODED_HEADER = {'Content-Type': 'application/x-www-form-urlencoded'}
    JSON_CONTENT_HEADER = {'Content-Type': 'application/json'}

    def __init__(self, api_key: str, base_url: str, verify: bool, proxy: bool):
        self.api_key = api_key
        self.base_headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=self.base_headers)

    def http_request(self, method: str, url_suffix: str, params: Optional[Dict] = None, data: Optional[Dict] = None,
                     headers: Optional[Dict] = None, files: Optional[Dict] = None):
        """
        Wrapper for Base Client http request. Uses error handler to catch errors returned by FraudWatch and returning
        an exception with more precise description for the exception
        Args:
            method (str): The HTTP method to perform ('POST', 'GET', 'PUT').
            url_suffix (str): The url suffix of the API call.
            params (Optional[Dict]): Additional query params to be sent.
            data (Optional[Dict]): Additional data to be sent.
            headers (Optional[Dict]): Additional headers to be sent.
            files (Optional[Dict]): Additional files to be sent

        Returns:
            The HTTP response, or exception if exception occurred.
        """
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            data=data,
            headers=headers,
            files=files,
            error_handler=fraud_watch_error_handler
        )

    def incidents_list(self, brand: Optional[str] = None, status: Optional[str] = None, page: Optional[int] = None,
                       limit: Optional[int] = None, from_date: Optional[str] = None, to_date: Optional[str] = None):
        params = assign_params(
            brand=brand,
            status=status,
            page=page,
            limit=limit,
            to=to_date
        )

        # This is because 'from' is reserved word so it can't be used as key argument in assign_params.
        if from_date:
            params['from'] = from_date

        return self.http_request(
            method='GET',
            url_suffix='incidents',
            params=params
        )

    def incident_report(self, brand: str, incident_type: str, primary_url: str,
                        reference_id: Optional[str] = None, urls: Optional[List[str]] = None,
                        evidence: Optional[str] = None, instructions: Optional[str] = None):
        return self.http_request(
            method='POST',
            url_suffix='incidents',
            data=assign_params(
                brand=brand,
                type=incident_type,
                reference_id=reference_id,
                primary_url=primary_url,
                urls=urls,
                evidence=evidence,
                instructions=instructions
            ),
            headers={**self.base_headers, **self.URL_ENCODED_HEADER}
        )

    def incident_update(self, incident_id: str, brand: Optional[str] = None, reference_id: Optional[str] = None,
                        evidence: Optional[str] = None, instructions: Optional[str] = None):
        return self.http_request(
            method='PUT',
            url_suffix=f'incident/{incident_id}',
            data=assign_params(
                brand=brand,
                reference_id=reference_id,
                evidence=evidence,
                instructions=instructions
            ),
            headers={**self.base_headers, **self.URL_ENCODED_HEADER}
        )

    def incident_list_by_id(self, incident_id: str):
        return self.http_request(
            method='GET',
            url_suffix=f'incident/{incident_id}'
        )

    def incident_get_by_reference(self, reference_id: str):
        return self.http_request(
            method='GET',
            url_suffix=f'incident/reference/{reference_id}'
        )

    def incident_forensic_get(self, incident_id: str):
        return self.http_request(
            method='GET',
            url_suffix=f'incident/{incident_id}/forensic'
        )

    def incident_contact_emails_list(self, incident_id: str, page: Optional[int] = None, limit: Optional[int] = None):
        return self.http_request(
            method='GET',
            url_suffix=f'incident/{incident_id}/message',
            params=assign_params(
                page=page,
                limit=limit
            )
        )

    def incident_messages_add(self, incident_id: str, message_content: Any):
        return self.http_request(
            method='POST',
            url_suffix=f'incident/{incident_id}/message/add',
            data=message_content,
            headers={**self.base_headers, **self.JSON_CONTENT_HEADER}
        )

    def incident_urls_add(self, incident_id: str, urls: Dict[str, List[str]]):
        return self.http_request(
            method='POST',
            url_suffix=f'incident/{incident_id}/urls/add',
            data=urls,
            headers={**self.base_headers, **self.URL_ENCODED_HEADER}
        )

    def attachment_upload_command(self, incident_id: str, file: Any):
        return self.http_request(
            method='POST',
            url_suffix=f'incident/{incident_id}/upload',
            files=file
        )

    def brands_list(self, page: Optional[int] = None, limit: Optional[int] = None):
        return self.http_request(
            method='GET',
            url_suffix='account/brands',
            params=assign_params(
                page=page,
                limit=limit
            )
        )


''' HELPER FUNCTIONS '''


def fraud_watch_error_handler(res: Response):
    """
    FraudWatch error handler for any error occurred during the API request.
    This function job is to translate the known exceptions returned by FraudWatch
    to human readable exception to help the user understand why the request have failed.
    If error returned is not in the expected error format, raises the exception as is.
    Args:
        res (Any): The error response returned by FraudWatch.

    Returns:
        - raises DemistoException.
    """
    err_msg = f'Error in API call [{res.status_code}] - {res.reason}'
    try:
        # Try to parse json error response
        error_entry = res.json()
        message = error_entry.get('message')
        errors = error_entry.get('errors')
        if res.status_code == 403:
            err_msg += '\nMake sure your API token is valid and up-to-date'
        elif not message and not errors:
            err_msg += f'\n{json.dumps(error_entry)}'
        else:
            if message and errors:
                fraud_watch_error_reason = f'{message}: {errors}'
            else:
                fraud_watch_error_reason = message if message else errors
            err_msg += f'\n{fraud_watch_error_reason}'
        raise DemistoException(err_msg, res=res)
    except ValueError:
        err_msg += f'\n{res.text}'
        raise DemistoException(err_msg, res=res)


def get_and_validate_positive_int_argument(args: Dict, argument_name: str, lower_bound: int = MINIMUM_POSITIVE_VALUE,
                                           upper_bound: Optional[int] = None) -> Optional[int]:
    """
    Extracts int argument from Demisto arguments.
    If argument exists, validates that:
    - lower_bound <= argument's value.
    - argument's value <= maximum_bound if maximum_bound is not None.

    Args:
        args (Dict): Demisto arguments.
        argument_name (str): The name of the argument to extract.
        lower_bound (int): Lower number bound of the argument value.
        upper_bound (Optional[int]): Maximum number bound of the argument value, if given.

    Returns:
        - (int): If argument exists and is between 'lower_bound' and 'maximum_bound', returns argument.
        - (None): If argument does not exist, returns None.
        - (Exception): If argument exists and is lower than 'lower_bound' or
                       higher than 'maximum_bound' (if 'maximum_bound' exists), raises DemistoException.
    """
    argument_value = arg_to_number(args.get(argument_name), arg_name=argument_name)
    if not argument_value:
        return None
    if argument_value < lower_bound:
        raise DemistoException(f'{argument_name} should be equal or higher than {lower_bound}')
    if upper_bound and upper_bound < argument_value:
        raise DemistoException(f'{argument_name} should be equal or lower than {upper_bound}')

    return argument_value


def get_time_parameter(arg: Optional[str]):
    """
    parses arg into date time object with aware time zone if 'arg' exists.
    If no time zone is given, sets timezone to UTC.
    Returns the date time object created.
    Args:
        arg (str): The argument to turn into aware date time.

    Returns:
        - (None) If 'arg' is None, returns None.
        - (datetime): If 'arg' is exists, returns date time.
    """
    maybe_unaware_date = arg_to_datetime(arg, is_utc=True)
    if not maybe_unaware_date:
        return None

    aware_time_date = maybe_unaware_date if maybe_unaware_date.tzinfo else UTC_TIMEZONE.localize(
        maybe_unaware_date)

    return aware_time_date


''' COMMAND FUNCTIONS '''


def get_page_and_limit_args(args: Dict, minimum_page_size: int = MINIMUM_POSITIVE_VALUE,
                            maximum_page_size: int = MAX_PAGE_SIZE_VALUE) -> Tuple[int, int]:
    """
    Receives demisto argument, and extract the relevant arguments for limits and paging:
    'page', 'page_size', 'limit'.
    Follows the logic:
    - 'limit' argument cannot be specified with 'page' or 'page_size' argument.
    - 'page_size' argument is within its expected lower/upper bounds.
    - If 'limit' is not given, and 'page_size' is, sets 'limit' value to 'page_size' value.
    - If 'limit' is not given, and 'page_size' is not given, sets 'limit' value to 'DEFAULT_PAGE_SIZE_VALUE' value.
    Args:
        args (Dict): Demisto argument.
        minimum_page_size (int): lower_bound for page size, default is 'MINIMUM_POSITIVE_VALUE' (1).
        maximum_page_size (int): upper_bound for page size, default is 'MAX_PAGE_SIZE_VALUE' (200).

    Returns:
        - (int, int): 'page', 'limit' extracted, or their default values used.
        - (DemistoException): If arguments don't follow the expected logic mentioned.
    """
    page = get_and_validate_positive_int_argument(args, 'page')
    page_size = get_and_validate_positive_int_argument(args, 'page_size', lower_bound=minimum_page_size,
                                                       upper_bound=maximum_page_size)
    limit = get_and_validate_positive_int_argument(args, 'limit')
    if limit and (page_size or page):
        raise DemistoException('''Limit argument cannot be given with 'page_size' or 'page' argument.''')
    if not limit and page_size:
        limit = page_size
    if not limit:
        limit = DEFAULT_PAGE_SIZE_VALUE
    if not page:
        page = MINIMUM_POSITIVE_VALUE

    return page, limit


def fetch_incidents_command(client: Client, params: Dict, last_run: Dict):
    """
    Fetches new incidents from FraudWatch.
    Because of FraudWatch limitation, such as 'from_date' being accurate only by day, and incidents returned
    are not ordered by their date opened.
    1) First_fetch time is limited to 1 day.
    2) Every fetch_incidents call, we will fetch all the pages from the day of the time stamp saved in last run.
    3) Filter all incidents that their date opened was earlier than last saved time stamp.
    4) Sort the remained incidents by their date opened.
    5) Return the first 'max_fetch' incidents in the sorted list.
    Limiting first_fetch is needed because we must traverse all incidents that might be relevant, therefore the
    list cannot be very large.
    Uses Demisto last run parameters in the following way:
    - 'last_fetch_time' - The latest time fetching was done. Keeps track of incidents to be fetched by their date.

    Args:
        client (Client): FraudWatch client to perform API call to fetch incidents.
        params (Dict): Demisto params.
        last_run (Dict): Demisto last run.

    Returns:
        (List[Dict], Dict): Incidents and new run parameters.
    """
    brand = params.get('brand')
    status = params.get('status')
    limit = arg_to_number(params.get('max_fetch', DEFAULT_PAGE_SIZE_VALUE))

    yesterday = get_time_parameter('1 day')
    first_fetch_time_string = params.get('first_fetch', '1 days').strip()
    minimum_date_opened_str = last_run.get('last_fetch_time', first_fetch_time_string)
    # Between yesterday date and last fetch date we choose the latest
    minimum_date_opened = max(get_time_parameter(minimum_date_opened_str), yesterday)

    from_date = minimum_date_opened.strftime(FRAUD_WATCH_DATE_FORMAT)
    incidents = []

    # Need to fetch all incidents because FraudWatch does not sort incidents based on dates.
    current_page = 1
    while True:
        raw_response = client.incidents_list(brand=brand, status=status, page=current_page, limit=MAX_PAGE_SIZE_VALUE,
                                             from_date=from_date)
        if raw_response.get('error'):
            raise DemistoException(
                f'''Error occurred while pulling incidents from FraudWatch: {raw_response.get('error')}''')
        temp_incidents = raw_response.get('incidents', [])
        if not temp_incidents:
            break
        incidents += temp_incidents
        current_page += 1

    incidents = [incident for incident in incidents
                 if get_time_parameter(incident.get('date_opened')) > minimum_date_opened]
    incidents.sort(key=lambda incident: incident.get('date_opened'))
    incidents = incidents[:limit]

    incidents_obj_list: List[Dict[str, Any]] = [{
        'name': f'''{incident.get('brand')}:{incident.get('identifier')}''',
        'type': 'FraudWatch Incident',
        'occurred': incident.get('date_opened'),
        'rawJSON': json.dumps(incident)
    } for incident in incidents]

    next_run = {
        'last_fetch_time': incidents[-1].get('date_opened') if incidents else minimum_date_opened_str
    }
    return incidents_obj_list, next_run


def test_module(client: Client, params: Dict) -> str:
    """
    Tests API connectivity and authentication.
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): FraudWatch client to perform the API call.
        params (Dict): Demisto params.

    Returns:
        (str): 'ok' if test passed, anything else will fail the test.
    """
    try:
        fetch_incidents_command(client, params, dict())
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
            e = DemistoException(message)
        raise e


def fraud_watch_incidents_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Gets a list of incidents from FraudWatch service with the possible filters:
    - Brand: Retrieve incidents which corresponds to the given brand. throws Exception if brand does not exist.
    - Status: Retrieve incidents which corresponds to the given status. Unknown status will return empty incident list.
    - Limit: Total number of Incidents in a page. The default limit is 20 and the maximum number is 200.
    - Page: Retrieve incidents by the given page number.
    - From Date: Retrieve alerts that their date opened is higher or equal to 'from' value.
                 Supports ISO and time range (<number> <time unit>, e.g., 12 hours, 7 days) formats.
                 If 'to' argument is not given, default value for 'to' is current day.
    - To Date: Retrieve alerts that their date opened is lower or equal to 'to' value.
               Supports ISO and time range (<number> <time unit>, e.g., 12 hours, 7 days) formats.
               If 'from' argument is not given, default value for 'from' is 12 months before 'to'.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown brand.
    - Invalid 'to_date' or 'from_date' values.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    brand = args.get('brand')
    status = args.get('status')
    page, limit = get_page_and_limit_args(args)

    if from_date := get_time_parameter(args.get('from')):
        from_date = from_date.strftime(FRAUD_WATCH_DATE_FORMAT)

    if to_date := get_time_parameter(args.get('to')):
        to_date = to_date.strftime(FRAUD_WATCH_DATE_FORMAT)

    if from_date and not to_date:
        to_date = get_time_parameter('tomorrow').strftime(FRAUD_WATCH_DATE_FORMAT)

    raw_responses = []
    outputs = []
    count = limit
    while limit > 0:
        raw_response = client.incidents_list(brand, status, page, MAX_PAGE_SIZE_VALUE, from_date, to_date)
        incidents = raw_response.get('incidents', [])
        if not incidents:
            break
        if raw_response.get('error'):
            raise DemistoException(f'''Error occurred during the call to FraudWatch: {raw_response.get('error')}''')
        raw_responses.append(raw_response)
        outputs.extend(incidents)
        limit -= MAX_PAGE_SIZE_VALUE
        page += 1

    final_raw_responses = raw_responses[:count]
    final_outputs = outputs[:count]

    return CommandResults(
        outputs_prefix='FraudWatch.Incident',
        outputs=final_outputs,
        outputs_key_field='identifier',
        raw_response=final_raw_responses,
        readable_output=tableToMarkdown('FraudWatch Incidents', final_outputs, INCIDENT_LIST_MARKDOWN_HEADERS,
                                        removeNull=True)
    )


def fraud_watch_incident_report_command(client: Client, args: Dict) -> CommandResults:
    """
    Report an incident to FraudWatch service:
    - Brand(Required): The brand associated to the reported incident.
    - Incident Type(Required): The type of the incident to be associated to the reported incident.
         - possible values: ['phishing' => Phishing,
                           'vishing' => Vishing,
                           'brand_abuse' => Brand Abuse,
                           'malware' => Malware,
                           'social_media_brand_abuse' => Social Media,
                           'mobile_app_unauthorized' => Mobile App,
                           'pac_file' => PAC File,
                           'pharming' => Pharming,
                           'messaging' => Messaging,
                           'dmarc_email_server' => DMARC]
           left side is the parameter to be sent, right side is the way it will be shown in FraudWatch User Interface.
    - Reference ID: Reference ID to be associated to the reported incident. Should be unique.
                    Reference ID can be used later to retrieve specific incident by its reference id.
    - Primary URL(Required): Primary URL of the reported incident.
    - Urls: Additional urls in addition to primary URL to be associated to the reported incident.
    - Evidence: Evidence to be added (such as logs, etc...) to the reported incident.
    - Instructions: Additional instructions to be added for FraudWatch Security Team.

    Known errors that causes error to be returned by FraudWatch service:
    - Not given or unknown brand.
    - Not given or unknown incident type.
    - Not given primary url.
    - No data given.
    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    brand: str = args.get('brand')  # type: ignore
    incident_type: str = args.get('type')  # type: ignore
    primary_url: str = args.get('primary_url')  # type: ignore
    reference_id = args.get('reference_id')
    urls = args.get('urls')
    evidence = args.get('evidence')
    instructions = args.get('instructions')

    raw_response = client.incident_report(brand, incident_type, primary_url, reference_id, urls, evidence, instructions)

    return CommandResults(
        outputs_prefix='FraudWatch.Incident',
        outputs=raw_response,
        outputs_key_field='identifier',
        raw_response=raw_response,
        readable_output=tableToMarkdown("Created FraudWatch Incident", raw_response, removeNull=True)
    )


def fraud_watch_incident_update_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the incident ID corresponding to the given incident_id with given arguments values:
    - Incident ID(Required): The ID of the incident to be updated.
    - Brand: Updates this to be the brand associated to the incident which corresponds to given incident id.
    - Reference ID: Reference ID to be associated to the incident which corresponds to given incident id.
                    Should be unique. Reference ID can be used later to retrieve specific incident by its reference id.
    - Evidence: Evidence to be added (such as logs, etc...) to the incident.
    - Instructions: Add Additional instructions to be added for FraudWatch Security
                    Team to the incident which corresponds to given incident id.

    At least one of 'Brand', 'Reference ID', 'Evidence', 'Instructions' must be given.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.
    - Not given or unknown brand.
    - No data given.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore
    brand = args.get('brand')
    reference_id = args.get('reference_id')
    evidence = args.get('evidence')
    instructions = args.get('instructions')

    if all(argument is None for argument in [brand, reference_id, evidence, instructions]):
        return CommandResults(readable_output=f'### Could not update incident: {incident_id} - No data was given.')

    raw_response = client.incident_update(incident_id, brand, reference_id, evidence, instructions)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'### Incident with ID {incident_id} was updated successfully'
    )


def fraud_watch_incident_get_by_identifier_command(client: Client, args: Dict) -> CommandResults:
    """
    Gets an incident from FraudWatch service by its reference ID or incident ID:
    - Incident ID: The ID of the incident to be retrieved.
    - Reference ID: Reference id of the incident to be retrieved.
                    In case more than one incident has the corresponding reference id, FraudWatch service
                    returns the incident with the latest 'date_opened' field.

    Exactly one of 'Incident ID', 'Reference ID' should be given, else DemistoException will be raised.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.
    - Unknown reference_id id.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore
    reference_id: str = args.get('reference_id')  # type: ignore

    if (incident_id and reference_id) or (not incident_id and not reference_id):
        raise DemistoException('Exactly one of reference id or incident id must be given.')

    if incident_id:
        raw_response = client.incident_list_by_id(incident_id)
    else:
        raw_response = client.incident_get_by_reference(reference_id)

    return CommandResults(
        outputs_prefix='FraudWatch.Incident',
        outputs=raw_response,
        outputs_key_field='identifier',
        raw_response=raw_response,
        readable_output=tableToMarkdown("FraudWatch Incident", raw_response, removeNull=True)
    )


def fraud_watch_incident_forensic_get_command(client: Client, args: Dict) -> CommandResults:
    """
    Gets forensic data of an incident which corresponds to the given incident ID:
    - Incident ID (Required): The ID of the incident to have its forensic data retrieved.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore

    raw_response = client.incident_forensic_get(incident_id)
    outputs = remove_empty_elements(raw_response)
    if outputs:
        outputs['identifier'] = incident_id

    return CommandResults(
        outputs_prefix='FraudWatch.IncidentForensicData',
        outputs=outputs,
        outputs_key_field='identifier',
        raw_response=raw_response,
        readable_output=tableToMarkdown("FraudWatch Incident Forensic Data", outputs,
                                        removeNull=True)
    )


def fraud_watch_incident_contact_emails_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Provides contact emails for the incident which corresponds to the given incident ID:
    - Incident ID (Required): The ID of the incident to have its email contacts data retrieved.
    - Limit: Total number of contact emails in a page. The default limit is 20 and the maximum number is 200.
    - Page: Retrieve contact emails by the given page number.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.
    - Page index out of bounds.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore
    page, limit = get_page_and_limit_args(args)

    raw_responses = []
    count = limit

    try:
        while limit > 0:
            raw_response = client.incident_contact_emails_list(incident_id, page, MAX_PAGE_SIZE_VALUE)
            if not raw_response:
                break
            raw_responses.extend(raw_response)
            limit -= MAX_PAGE_SIZE_VALUE
            page += 1
    except DemistoException as e:
        if 'Contact email not found' in str(e):
            page_error_msg = f'''Make sure page index: {page} is within bounds.''' if page else ''
            unknown_incident_msg = f'''Make sure incident id: {incident_id} is correct.'''
            raise DemistoException(
                f'''Error occurred. {page_error_msg}'''
                f' {unknown_incident_msg}')
        raise e

    outputs = [dict(output, identifier=incident_id) for output in raw_responses]

    final_raw_responses = raw_responses[:count]
    final_outputs = outputs[:count]

    return CommandResults(
        outputs_prefix='FraudWatch.IncidentContacts',
        outputs=final_outputs,
        outputs_key_field='noteId',
        raw_response=final_raw_responses,
        readable_output=tableToMarkdown("FraudWatch Incident Contacts Data", final_outputs,
                                        ['noteId', 'incident_id', 'subject', 'creator', 'content', 'date'],
                                        removeNull=True)
    )


def fraud_watch_incident_messages_add_command(client: Client, args: Dict):
    """
    Add a new message to be associated to the incident which corresponds to the given incident ID:
    - Incident ID (Required): The ID of the incident to add a message to its email contacts.
    - Message Content (Required): Content of the message.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore
    message_content = args.get('message_content')

    raw_response = client.incident_messages_add(incident_id, message_content)

    human_readable = f'### Message for incident id {incident_id} was added successfully.'

    return CommandResults(
        raw_response=raw_response,
        readable_output=human_readable
    )


def fraud_watch_incident_urls_add_command(client: Client, args: Dict) -> CommandResults:
    """
    Adds additional urls to the incident which corresponds to the given incident ID:
    - Incident ID (Required): The ID of the incident to add additional urls to.
    - Urls: Additional urls to be added to the incident that matches 'Incident ID'.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore
    urls: Dict[str, List[str]] = {
        'urls[]': argToList(args.get('urls'))
    }

    raw_response = client.incident_urls_add(incident_id, urls)

    return CommandResults(
        outputs_prefix='FraudWatch.IncidentUrls',
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown("FraudWatch Incident Urls", raw_response, removeNull=True)
    )


def fraud_watch_attachment_upload_command(client: Client, args: Dict):
    """
    Adds a new file attachment to the incident which corresponds to the given incident ID.
    - Incident ID (Required): The ID of the incident to add additional urls to.
    - File Attachment: Entry id of the attachment to be added to the incident which corresponds to Incident ID.

    Known errors that causes error to be returned by FraudWatch service:
    - Unknown incident id.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    incident_id: str = args.get('incident_id')  # type: ignore
    entry_id = args.get('entry_id')

    try:
        # entry id of uploaded file to war room
        file_info = demisto.getFilePath(entry_id)
        file = open(file_info['path'], 'rb')
    except Exception:
        raise DemistoException(F"Entry {entry_id} does not contain a file.")

    files = [
        ('incident_attachment',
         (file_info['name'], file))
    ]
    raw_response = client.attachment_upload_command(incident_id, files)

    return CommandResults(
        raw_response=raw_response,
        # change to name and not entry ID
        readable_output=f'''### File {file_info['name']} was uploaded successfully to incident: {incident_id}'''
    )


def fraud_watch_brands_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Gets a list of brands from FraudWatch service:
    - Limit: Total number of brands in a page. The default limit is 20, minimum number is also 20
             and the maximum number is 100.
    - Page: Retrieve brands by the given page number.

    Args:
        client (Client): FraudWatch client to perform the API calls.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    page, limit = get_page_and_limit_args(args, minimum_page_size=MINIMUM_PAGE_SIZE_BRANDS,
                                          maximum_page_size=MAX_PAGE_SIZE_BRANDS)
    raw_responses = []
    outputs = []
    count = limit
    while limit > 0:
        raw_response = client.brands_list(page, MAX_PAGE_SIZE_BRANDS)
        brands_list = raw_response.get('brands', [])
        if not brands_list:
            break
        raw_responses.append(raw_response)
        outputs.extend(brands_list)
        limit -= MAX_PAGE_SIZE_BRANDS
        page += 1

    final_raw_responses = raw_responses[:count]
    final_outputs = outputs[:count]

    return CommandResults(
        outputs_prefix='FraudWatch.Brand',
        outputs=final_outputs,
        outputs_key_field='name',
        raw_response=final_raw_responses,
        readable_output=tableToMarkdown("FraudWatch Brands", final_outputs, ['name', 'active', 'client'],
                                        removeNull=True)
    )


''' MAIN FUNCTION '''


def main() -> None:
    """
        Main function, parses params and runs command functions.
    """
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    credentials = params.get('credentials')
    api_key = credentials.get('password')
    if not api_key:
        raise DemistoException(
            'API token was not given. Please insert your API token. See documentation for further info')

    base_url = urljoin(params.get('base_url', DEFAULT_URL), 'v1/')

    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            api_key=api_key,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client, params))

        elif command == 'fetch-incidents':
            incidents, next_run = fetch_incidents_command(client, params, demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'fraudwatch-incidents-list':
            return_results(fraud_watch_incidents_list_command(client, args))

        elif command == 'fraudwatch-incident-report':
            return_results(fraud_watch_incident_report_command(client, args))

        elif command == 'fraudwatch-incident-update':
            return_results(fraud_watch_incident_update_command(client, args))

        elif command == 'fraudwatch-incident-get-by-identifier':
            return_results(fraud_watch_incident_get_by_identifier_command(client, args))

        elif command == 'fraudwatch-incident-forensic-get':
            return_results(fraud_watch_incident_forensic_get_command(client, args))

        elif command == 'fraudwatch-incident-contact-emails-list':
            return_results(fraud_watch_incident_contact_emails_list_command(client, args))

        elif command == 'fraudwatch-incident-messages-add':
            return_results(fraud_watch_incident_messages_add_command(client, args))

        elif command == 'fraudwatch-incident-urls-add':
            return_results(fraud_watch_incident_urls_add_command(client, args))

        elif command == 'fraudwatch-incident-attachment-upload':
            return_results(fraud_watch_attachment_upload_command(client, args))

        elif command == 'fraudwatch-brands-list':
            return_results(fraud_watch_brands_list_command(client, args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
