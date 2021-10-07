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

BASE_URL = 'https://api.hackerone.com/v1/'
DEFAULT_MAX_FETCH = "15"
DEFAULT_FIRST_FETCH = "3 days"

HTTP_ERROR = {
    401: "Unauthenticated. Check the configured Username and API Key.",
    403: "Forbidden. Verify the URL.",
    404: "Please verify the value of Program Handle as well as the value of the URL. "
         "\n Or the URL is not reachable. Please try again later.",
    500: "The server encountered an internal error for HackerOne and was unable to complete your request."
}

MESSAGES = {
    "Common_ERROR_MESSAGE": "Unable to retrieve the data based on arguments.",
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
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, auth: tuple):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def http_request(self, *args, **kwargs) -> Any:
        """
        Function to make http requests using inbuilt _http_request() method.

        :return: response from the request
        :rtype: ``Dict``

        """

        kwargs['error_handler'] = self.exception_handler
        return super()._http_request(*args, **kwargs)

    @staticmethod
    def exception_handler(response: requests.models.Response):
        """
        Handle error in the response and display error message based on status code.

        :type response: ``requests.models.Response``
        :param response: response from API.

        :raises: raise DemistoException based on status code of response.
        """

        if response.headers.get("Content-Type") and ("text/html" in response.headers["Content-Type"]):
            raise DemistoException(MESSAGES['Common_ERROR_MESSAGE'])

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
                raise DemistoException(MESSAGES['Common_ERROR_MESSAGE'])

            for error in errors:
                msg = error.get("detail", error.get("title", MESSAGES['Common_ERROR_MESSAGE']))

                if err_msg:
                    err_msg = f"{err_msg}\n{msg}"
                else:
                    err_msg = msg

        raise DemistoException(err_msg)


''' HELPER FUNCTIONS '''


def retrieve_fields(arg: str) -> List[str]:
    """Strip and filter out the empty elements from the string.

    :type arg: ``str``
    :param arg: The string from which we want to filter out the empty elements.

    :return: Filtered out result.
    :rtype: ``List[str]``
     """
    return [x.strip() for x in arg.split(",") if x.strip()]


def validate_filter_by_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate filters in params, raise ValueError on invalid arguments.

    :type args: ``Dict[str, Any]``
    :param args: The filter arguments provided by the user.

    :return: Parameters related to the filters.
    :rtype: ``Dict[str, Any]``
    """
    params = {}

    program_handle = retrieve_fields(args.get("program_handle", ""))
    if not program_handle:
        raise ValueError(MESSAGES['PROGRAM_HANDLE'])
    params["filter[program][]"] = program_handle

    if args.get("severity"):
        params['filter[severity][]'] = args["severity"]

    if args.get("state"):
        params['filter[state][]'] = args["state"]

    if not args.get("filter_by"):
        return params

    try:
        filters = json.loads(args["filter_by"].strip())
        for key, value in filters.items():
            key, value = key.strip(), value.strip()
            if not key or not value:
                continue

            if "[]" in key:
                params[key] = retrieve_fields(value)
            else:
                params[key] = value

    except (json.JSONDecodeError, json.decoder.JSONDecodeError, AttributeError):
        raise ValueError(MESSAGES["FILTER"])

    remove_nulls_from_dictionary(params)
    return params


def validate_fetch_incidents_parameters(params: dict) -> Dict[str, Any]:
    """
    Validate fetch incidents params, throw ValueError on non-compliant arguments

    :type params: ``Dict[str, Any]``
    :param params: Parameters to be validated for fetching the incidents.

    return: params to be passed for fetching incidents.
    :rtype: ``Dict``
    """
    fetch_params: Dict[str, Any] = {}
    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH).strip())

    if (max_fetch is None) or (not 0 < max_fetch <= 100):
        raise ValueError(MESSAGES["INVALID_MAX_FETCH"].format(max_fetch))
    fetch_params["page[size]"] = max_fetch

    fetch_params["sort"] = "reports.created_at"

    fetch_params.update(
        validate_filter_by_arguments(params))

    first_fetch = arg_to_datetime(params.get("first_fetch", "3 days").strip())

    if first_fetch is None:
        raise ValueError(MESSAGES["INVALID_FIRST_FETCH"].format(params.get("first_fetch")))
    fetch_params["filter[created_at__gt]"] = first_fetch.strftime(DATE_FORMAT)

    remove_nulls_from_dictionary(fetch_params)
    return fetch_params


def validate_common_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate page_size and page_number argument, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    params: Dict[str, Any] = {}

    page_size = arg_to_number(args.get("page_size"))
    params["page[size]"] = 50
    if page_size is not None:
        if page_size <= 0 or page_size > 100:
            raise ValueError(MESSAGES['PAGE_SIZE'].format(page_size))
        params["page[size]"] = page_size

    page_number = arg_to_number(args.get("page_number"))
    if page_number is not None:
        if page_number < 0 or page_number >= 2147483648:
            raise ValueError(MESSAGES['PAGE_NUMBER'].format(page_number))
        params["page[number]"] = page_number

    return params


def validate_report_list_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate all report list arguments, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    params = validate_common_args(args)

    filter_by_keyword = args.get("filter_by_keyword")
    if filter_by_keyword:
        params["filter[keyword]"] = filter_by_keyword

    sort_by = retrieve_fields(args.get("sort_by", ""))
    if sort_by:
        params["sort"] = ["-reports." + sort_value[1:] if sort_value.startswith("-") else "reports." + sort_value
                          for sort_value in sort_by]

    args["state"] = retrieve_fields(args.get("state", ""))

    args["severity"] = retrieve_fields(args.get("severity", ""))

    args["filter_by"] = args.get("advanced_filter", "")
    params.update(
        validate_filter_by_arguments(args))

    remove_nulls_from_dictionary(params)
    return params


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


def remove_empty_elements_from_list(response: Any) -> Any:
    """
     Recursively remove empty lists, empty dicts, empty string or None elements from a dictionary.

    :type response: ``Any``
    :param response: Input dictionary.

    :return: Dictionary with all empty lists,empty string and empty dictionaries removed.
    :rtype: ``Any``
    """

    def empty(x):
        return x is None or x == '' or x == {} or x == []

    if not isinstance(response, (dict, list)):
        return response
    elif isinstance(response, list):
        return [v for v in (remove_empty_elements_from_list(v) for v in response) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_from_list(v))
                                  for k, v in response.items()) if not empty(v)}


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict) -> str:
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
    is_fetch = params.get("isFetch", False)
    response = client.http_request(method='GET', url_suffix=URL_SUFFIX['PROGRAMS'],
                                   params={"page[size]": 1}, resp_type="response", ok_codes=(200, 400))

    if response.status_code == 400:
        raise DemistoException(HTTP_ERROR[401])

    if is_fetch:
        fetch_incidents(client, {}, params)

    return 'ok'


def fetch_incidents(client: Client, last_run: dict, params: Dict) -> Tuple[dict, list]:
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
    fetch_params = validate_fetch_incidents_parameters(params)
    first_fetch = fetch_params["filter[created_at__gt]"]

    fetch_params["page[number]"] = last_run.get("next_page", 1)
    fetch_params["filter[created_at__gt]"] = last_run.get("current_created_at", first_fetch)  # type: ignore

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["REPORTS"], params=fetch_params)

    results = response.get('data', [])

    if not results:
        next_run = last_run
        next_run["current_created_at"] = last_run.get("next_created_at", first_fetch)
        next_run["next_page"] = 1
        return next_run, []

    next_run = {"next_page": fetch_params["page[number]"] + 1,
                "current_created_at": fetch_params["filter[created_at__gt]"],
                "next_created_at": results[-1].get("attributes", {}).get("created_at")}

    report_ids = last_run.get("report_ids", [])

    if next_run.get("next_created_at") != last_run.get("next_created_at"):
        report_ids = []

    incidents = []
    for result in results:
        if result.get("id") in report_ids:
            continue
        report_ids.append(result.get("id"))
        incidents.append({
            'name': result.get('attributes', {}).get('title', ''),
            'occurred': result.get('attributes', {}).get('created_at'),
            'rawJSON': json.dumps(result)
        })

    next_run["report_ids"] = report_ids

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

    params = validate_common_args(args)

    # Sending http request
    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["PROGRAMS"], params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("programs"))

    # Creating the Human Readable
    hr_response = prepare_hr_for_programs(result)

    # Creating the Context data
    context_data = remove_empty_elements_from_list(result)

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

    params = validate_report_list_args(args)
    # Sending http request
    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["REPORTS"],
                                   params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("reports"))

    # Creating the Human Readable
    hr_response = prepare_hr_for_reports(result)
    # Creating the Context data
    context_data = remove_empty_elements_from_list(result)

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
    url = params.get('url', BASE_URL)
    credentials = params.get("username", {})
    username = credentials.get('identifier').strip()
    password = credentials.get('password')

    command = demisto.command()

    demisto.debug(f'[HackerOne] Command being called is {command}')

    try:
        client = Client(
            base_url=url,
            verify=verify_certificate,
            proxy=proxy,
            auth=(username, password)
        )
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
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
