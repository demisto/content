from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import traceback
import demistomock as demisto
from typing import Callable, Dict, Tuple, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

URL_SUFFIX = {
    "REPORTS": "reports",
    "PROGRAMS": "me/programs"
}
API_VERSION = 'v1'
BASE_URL = 'https://api.hackerone.com'
DEFAULT_MAX_FETCH = "15"
DEFAULT_FIRST_FETCH = "3 days"
INT32 = 2147483647
LOWER_BOUND = 1
MAXIMUM_PAGE_SIZE = 100
MAXIMUM_LIMIT = 1000
DEFAULT_PAGE_SIZE = 50
HTTP_ERROR = {
    401: "Unauthenticated. Check the configured Username and API Key.",
    403: "Forbidden. Verify the URL.",
    404: "Please verify the value of Program Handle as well as the value of the URL. "
         "\n Or the URL is not reachable. Please try again later.",
    500: "The server encountered an internal error for HackerOne and was unable to complete your request."
}

MESSAGES = {
    "COMMON_ERROR_MESSAGE": "Unable to retrieve the data based on arguments.",
    "PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 100.",
    "PAGE_NUMBER": "{} is an invalid value for page number. Page number must be between 1 and int32.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "PROGRAM_HANDLE": "Program Handle is invalid. It should not be empty.",
    "INVALID_MAX_FETCH": "{} is an invalid value for Maximum number of incidents per fetch. "
                         "It must be between 1 and 100.",
    "INVALID_FIRST_FETCH": "{} is an invalid value for 'First fetch time interval'. "
                           "It should be a valid date or relative timestamp. "
                           "For example: '2 days', '2 months' or of the format 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "FILTER": 'Please provide filter in a valid JSON format. Format accepted- \' '
              '{"attribute1" : "value1, value2" , "attribute2" : "value3, value4"} \'.',
    "INVALID_POSITIVE_INT": "{} is an invalid value for {}. It must be between {} and {}.",
    "INVALID_ARGUMENT": "Limit argument cannot be given with 'page_size' or 'page_number' argument."
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, auth: tuple, max_fetch: Optional[int],
                 first_fetch: str,
                 program_handle: List, severity: str, state: str, filters: str):
        self.max_fetch = max_fetch
        self.first_fetch = first_fetch
        self.program_handle = program_handle
        self.severity = severity
        self.state = state
        self.filters = filters
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def report_list(self, params: Dict) -> Dict:
        """
        Returns response
        :type params: ``Dict``
        :param params: Query Parameters to be passed.

        :return: API response
        :rtype: ``Dict``
        """

        return self._http_request(method="GET", url_suffix=URL_SUFFIX["REPORTS"],
                                  params=params, error_handler=self.exception_handler)

    def program_list(self, params: Dict) -> Dict:
        """
        Returns response
        :type params: ``Dict``
        :param params: Query Parameters to be passed.

        :return: API response
        :rtype: ``Dict``
        """

        return self._http_request(method="GET", url_suffix=URL_SUFFIX["PROGRAMS"], params=params,
                                  error_handler=self.exception_handler)

    @staticmethod
    def exception_handler(response: requests.models.Response):
        """
        Handle error in the response and display error message based on status code.

        :type response: ``requests.models.Response``
        :param response: response from API.

        :raises: raise DemistoException based on status code of response.
        """

        if response.headers.get("Content-Type") and ("text/html" in response.headers["Content-Type"]):
            raise DemistoException(MESSAGES['COMMON_ERROR_MESSAGE'])

        err_msg = None
        if response.status_code == 401:
            err_msg = HTTP_ERROR[401]

        elif response.status_code >= 500:
            err_msg = HTTP_ERROR[500]

        elif response.status_code == 404:
            err_msg = HTTP_ERROR[404]

        elif response.status_code == 403:
            err_msg = HTTP_ERROR[403]

        else:

            # Parse json error response
            errors = response.json().get("errors", [])
            if not errors:
                raise DemistoException(MESSAGES['COMMON_ERROR_MESSAGE'])

            for error in errors:
                msg = error.get("detail", error.get("title", MESSAGES['COMMON_ERROR_MESSAGE']))

                if err_msg:
                    err_msg = f"{err_msg}\n{msg}"
                else:
                    err_msg = msg

        raise DemistoException(err_msg)


''' HELPER FUNCTIONS '''


def remove_duplicates(data) -> List:
    """
    Remove duplicates from list
    :type data: ``List``
    :param data: list of response

    :return: list of unique response
    :rtype: ``List``
    """
    cleaned_list = []  # type: ignore

    for entry in data:
        if entry not in cleaned_list:
            cleaned_list.append(entry)

    return cleaned_list


def prepare_filter_by_arguments(program_handle, severity, state, filters) -> Dict[str, Any]:
    """
    Prepares params for the filters provided by user

    :type program_handle: ``List``
    :param program_handle: The program handle provided by the user.

    :type severity: ``Any``
    :param severity: Severity level provided by user.

    :type state: ``Any``
    :param state: State provided by user.

    :type filters: ``str``
    :param filters: The advanced_filter argument provided by the user.

    :return: Parameters related to the filters.
    :rtype: ``Dict[str, Any]``
    """
    params = {"filter[program][]": program_handle, 'filter[severity][]': severity,
              'filter[state][]': state}

    if not filters:
        return params

    filters = json.loads(filters)
    for key, value in filters.items():
        key, value = key.strip(), value.strip()
        if not key or not value:
            continue

        if "[]" in key:
            params[key] = argToList(value)
        else:
            params[key] = value

    return params


def validate_fetch_incidents_parameters(max_fetch: Optional[int], program_handle: List, filters: str):
    """
    Validates fetch incident parameters, raise ValueError on invalid arguments.

    :type max_fetch: ``int``
    :param max_fetch: Maximum number of incidents per fetch provided by user.

    :type program_handle: ``List``
    :param program_handle: The program handle provided by the user.

    :type filters: ``str``
    :param filters: The advanced_filter argument provided by the user.

    """
    if not 0 < max_fetch <= 100:  # type:ignore
        raise ValueError(MESSAGES["INVALID_MAX_FETCH"].format(max_fetch))

    if not program_handle:
        raise ValueError(MESSAGES['PROGRAM_HANDLE'])

    if filters:
        try:
            json.loads(filters)
        except (json.JSONDecodeError, json.decoder.JSONDecodeError, AttributeError):
            raise ValueError(MESSAGES["FILTER"])


def prepare_fetch_incidents_parameters(max_fetch, time_to_fetch, program_handle, severity, state, filters, page) -> \
        Dict[str, Any]:
    """
    Prepare fetch incidents params
    :type max_fetch: ``int``
    :param max_fetch: Maximum number of incidents per fetch provided by user.

    :type time_to_fetch: ``str``
    :param time_to_fetch: Date or relative timestamp to start fetching incidents from.

    :type program_handle: ``List``
    :param program_handle: The program handle provided by the user.

    :type severity: ``str``
    :param severity: Severity level provided by user.

    :type state: ``str``
    :param state: State provided by user.

    :type filters: ``str``
    :param filters: The advanced_filter argument provided by the user.

    :type page: ``str``
    :param page: Page number to retrieve next records.

    """

    fetch_params: Dict[str, Any] = {"page[size]": max_fetch, "sort": "reports.created_at",
                                    "page[number]": page}

    fetch_params.update(
        prepare_filter_by_arguments(program_handle, severity, state, filters))

    fetch_params["filter[created_at__gt]"] = arg_to_datetime(time_to_fetch).isoformat()[:-6]  # type:ignore

    return assign_params(**fetch_params)


def validate_report_list_args(args):
    """
    Validates all report list arguments, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.
    """

    filters = args.get("advanced_filter", "")
    if filters:
        try:
            json.loads(filters)
        except (json.JSONDecodeError, json.decoder.JSONDecodeError, AttributeError):
            raise ValueError(MESSAGES["FILTER"])


def prepare_report_list_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Preapare params for hackerone-report-list command.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    params: Dict[str, Any] = {

        "filter[keyword]": args.get("filter_by_keyword")
    }

    sort_by = argToList(args.get("sort_by", ""))
    if sort_by:
        params["sort"] = ["reports." + sort_value[1:] if sort_value.startswith("-") else "-reports." + sort_value
                          for sort_value in sort_by]

    program_handle = argToList(args.get("program_handle", ""))
    state = argToList(args.get("state", ""))
    severity = argToList(args.get("severity", ""))
    filters = args.get("advanced_filter", "")

    params.update(
        prepare_filter_by_arguments(program_handle, severity, state, filters))

    return assign_params(**params)


def prepare_hr_for_programs(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the programs in response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of programs.

    :return: Human Readable string containing programs.
    :rtype: ``str``
    """
    programs_hr = []
    for res in results:
        hr = {"Program ID": res.get("id")}
        attributes = res.get("attributes", {})
        hr["Handle"] = attributes.get("handle")
        hr["Created At"] = attributes.get("created_at")
        hr["Updated At"] = attributes.get("updated_at")
        programs_hr.append(hr)
    return tableToMarkdown("Program(s)", programs_hr,
                           headers=["Program ID", "Handle", "Created At", "Updated At"], removeNull=True)


def prepare_hr_for_reports(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the reports in response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of reports.

    :return: Human Readable string containing reports.
    :rtype: ``str``
    """
    reports_hr = []
    for res in results:
        hr = {"Report ID": res.get("id")}
        relationships = res.get("relationships", {})
        attributes = res.get("attributes", {})
        hr["Title"] = attributes.get("title")
        hr["State"] = attributes.get("state")
        severity = relationships.get("severity", {}).get("data", {}).get("attributes", {})
        hr["Severity"] = severity.get("rating", "")
        hr["Created At"] = attributes.get("created_at")
        hr["Vulnerability Information"] = attributes.get("vulnerability_information")
        reporter = relationships.get("reporter", {})
        relationship_data = reporter.get("data", {})
        inner_attributes = relationship_data.get("attributes", {})
        hr["Reporter Username"] = inner_attributes.get("username")

        reports_hr.append(hr)
    return tableToMarkdown("Report(s)", reports_hr,
                           headers=["Report ID", "Reporter Username", "Title", "State", "Severity", "Created At",
                                    "Vulnerability Information"], removeNull=True)


def get_and_validate_positive_int_argument(args: Dict, argument_name: str, lower_bound: int = 1,
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
    if argument_value is None:
        return None
    if not lower_bound <= argument_value <= upper_bound:  # type:ignore
        raise ValueError(
            MESSAGES["INVALID_POSITIVE_INT"].format(argument_value, argument_name, lower_bound, upper_bound))
    return argument_value


def get_page_and_limit_args(args: Dict):
    """
       Receives demisto argument, and extract the relevant arguments for limits and paging:
       'page_number', 'page_size', 'limit'.
       Follows the logic:
       - 'limit' argument cannot be specified with 'page' or 'page_size' argument.
       - 'page_size' argument is within its expected lower/upper bounds.
       - If 'limit' is not given, and 'page_size' is, sets 'limit' value to 'page_size' value.
       - If 'limit' is not given, and 'page_size' is not given, sets 'limit' value to 'DEFAULT_PAGE_SIZE' value.
       Args:
           args (Dict): Demisto argument.
       Returns:
           - (int, int): 'page', 'limit' extracted, or their default values used.
           - (DemistoException): If arguments don't follow the expected logic mentioned.
       """
    page = get_and_validate_positive_int_argument(args, 'page_number', lower_bound=LOWER_BOUND, upper_bound=INT32)
    page_size = get_and_validate_positive_int_argument(args, 'page_size', lower_bound=LOWER_BOUND,
                                                       upper_bound=MAXIMUM_PAGE_SIZE)
    limit = get_and_validate_positive_int_argument(args, 'limit', lower_bound=LOWER_BOUND, upper_bound=MAXIMUM_LIMIT)
    if limit and (page_size or page):
        raise ValueError(MESSAGES["INVALID_ARGUMENT"])
    if not limit and page_size:
        limit = page_size
    if not limit:
        limit = DEFAULT_PAGE_SIZE
    if not page:
        page = LOWER_BOUND

    return page, limit


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    if demisto.params().get('isFetch'):
        fetch_incidents(client, {})
    else:
        client.program_list(params={"page[size]": 1})

    return 'ok'


def fetch_incidents(client: Client, last_run: dict, ) -> Tuple[dict, list]:
    """Fetches incidents from HackerOne.

    :type client: ``Client``
    :param client: client to use

    :type last_run: ``Dict[str, str]``
    :param last_run: Last run returned by function demisto.getLastRun

    :type params: ``Dict[str, str]``
    :param params: Arguments for fetch-incident.

    :rtype: ``Tuple``
    :return: tuple of dictionary of next run and list of fetched incidents
    """
    validate_fetch_incidents_parameters(client.max_fetch, client.program_handle, client.filters)
    time_to_fetch = last_run.get("next_created_at", client.first_fetch)
    page_to_fetch = last_run.get("next_page", 1)
    fetch_params = prepare_fetch_incidents_parameters(client.max_fetch, time_to_fetch, client.program_handle,
                                                      client.severity, client.state, client.filters, page_to_fetch)

    response = client.report_list(params=fetch_params)

    results = response.get('data', [])
    next_run = last_run
    if not results:
        return next_run, []

    previous_report_ids = last_run.get("report_ids", [])
    new_report_ids = []
    incidents = []
    for result in results:
        if result.get("id") not in previous_report_ids:
            new_report_ids.append(result.get("id"))
            incidents.append({
                'name': result.get('attributes', {}).get('title', ''),
                'occurred': result.get('attributes', {}).get('created_at'),
                'rawJSON': json.dumps(result)
            })

    next_page = 1
    next_report_ids = new_report_ids
    created_at_last_report = results[-1].get("attributes", {}).get("created_at")

    if created_at_last_report == time_to_fetch:
        next_report_ids = previous_report_ids + new_report_ids
        next_page = page_to_fetch + 1

    next_run = {
        "next_page": next_page,
        "next_created_at": created_at_last_report,
        "report_ids": next_report_ids
    }

    return next_run, incidents


def hackerone_program_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves detailed information of all the programs that the user is a member of.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    page, limit = get_page_and_limit_args(args)
    raw_responses = []
    outputs = []
    count = limit
    while limit > 0:
        page_size = 100 if limit > 100 else limit
        params: Dict[str, Any] = {"page[size]": page_size, "page[number]": page}
        raw_response = client.program_list(params=params)
        program_list = raw_response.get('data', [])
        if not program_list:
            break
        raw_responses.append(raw_response)
        outputs.extend(program_list)
        limit -= 100
        page += 1

    response = remove_duplicates(raw_responses[:count])
    result = remove_duplicates(outputs[:count])

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("programs"))

    # Creating the Human Readable
    hr_response = prepare_hr_for_programs(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix="HackerOne.Program",
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def hackerone_report_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves list with detailed information of all the reports.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    validate_report_list_args(args)
    params = prepare_report_list_args(args)
    page, limit = get_page_and_limit_args(args)
    raw_responses = []
    outputs = []
    count = limit
    while limit > 0:
        page_size = 100 if limit > 100 else limit
        params["page[size]"] = page_size,
        params["page[number]"] = page
        raw_response = client.report_list(params=params)
        report_list = raw_response.get('data', [])
        if not report_list:
            break
        raw_responses.append(raw_response)
        outputs.extend(report_list)
        limit -= 100
        page += 1

    response = remove_duplicates(raw_responses[:count])
    result = remove_duplicates(outputs[:count])

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("reports"))

    # Creating the Human Readable
    hr_response = prepare_hr_for_reports(result)
    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix="HackerOne.Report",
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def main():
    """main function, parses params and runs command functions"""

    # Commands dictionary
    commands: Dict[str, Callable] = {
        'hackerone-report-list': hackerone_report_list_command,
        'hackerone-program-list': hackerone_program_list_command
    }

    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    url = urljoin(params.get('url', BASE_URL), API_VERSION)
    credentials = params.get("username", {})
    username = credentials.get('identifier').strip()
    password = credentials.get('password')

    command = demisto.command()

    demisto.debug(f'[HackerOne] Command being called is {command}')

    max_fetch = arg_to_number(
        params.get("max_fetch") if params.get('max_fetch').strip() else DEFAULT_MAX_FETCH)  # type:ignore
    first_fetch = params.get('first_fetch') if params.get('first_fetch').strip() else DEFAULT_FIRST_FETCH
    program_handle = argToList(params.get("program_handle", ""))
    severity = params.get('severity', "")
    state = params.get('state', "")
    filters = params.get("filter_by", "").strip()

    try:
        client = Client(
            base_url=url,
            verify=verify_certificate,
            proxy=proxy,
            auth=(username, password),
            max_fetch=max_fetch,
            first_fetch=first_fetch,
            program_handle=program_handle,
            severity=severity,
            state=state,
            filters=filters
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

        elif command in commands:
            args = {key: value.strip() for key, value in demisto.args().items()}
            return_results(commands[command](client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
