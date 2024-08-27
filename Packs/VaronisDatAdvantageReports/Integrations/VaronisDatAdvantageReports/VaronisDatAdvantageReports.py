import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pack version: 1.0


"""Varonis DSP Reports integration
Based on the Varonis Data Security Platform integration
Reengineered for the Reports API Engine by HeimDOS
"""


import traceback
from typing import Dict, Any, List, Tuple
from requests_ntlm import HttpNtlmAuth
import re


''' CONSTANTS '''

ALERT_STATUSES = {'open': 1, 'under investigation': 2, 'closed': 3}
ALERT_SEVERITIES = ['high', 'medium', 'low']
CLOSE_REASONS = {
    'none': 0,
    'resolved': 1,
    'misconfiguration': 2,
    'threat model disabled or deleted': 3,
    'account misclassification': 4,
    'legitimate activity': 5,
    'other': 6
}
DISPLAY_NAME_KEY = 'DisplayName'
SAM_ACCOUNT_NAME_KEY = 'SAMAccountName'
EMAIL_KEY = 'Email'


'''GLOBAL'''


TOKEN_FLAG = False


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def varonis_authenticate(self, username: str, password: str, url: str) -> Dict[str, Any]:
        """Gets the authentication token using the '/auth/win' API endpoint and ntlm authentication

        :type username: ``str``
        :param username: User name with domain 'Domain\\UserMame'

        :type password: ``str``
        :param password: Password

        :type url: ``str``
        :param url: Auth url

        :return: Dict containing the authentication token, token type, expiration time (sec)
        :rtype: ``Dict[str, Any]``

        :TOKEN_FLAG used to verify API is returning a JWT Token for test_module
        """
        global TOKEN_FLAG
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json, text/plain, */*',
                   'Accept-Encoding': 'gzip, deflate, sdch',
                   'Accept-Language': 'en-US,en;q=0.8'}

        ntlm = HttpNtlmAuth(username, password)
        response = self._http_request('GET', full_url=url, headers=headers, auth=ntlm)

        if isinstance(response, str):
            token = response
            TOKEN_FLAG = True
        else:
            demisto.debug(f"Unexpected response type: {type(response)} with content: {response}")
            raise ValueError("Expected a Token String but got something else")

        self._headers = {'Authorization': f'Bearer {token}'}

        return None

    def varonis_get_reports_metadata(self) -> List[Dict[str, Any]]:
        """Fetches the metadata of available reports."""
        headers = self._headers.copy()
        return self._http_request('GET', '/ReportAPI/api/search', headers=headers)

    def varonis_run_query(self, query: str) -> Dict[str, Any]:
        """Executes a query against the Reports API and returns the Location header with the query ID."""
        headers = self._headers.copy()
        request_body = {"Query": query}

        response = self._http_request(
            method='POST',
            url_suffix='/ReportAPI/api/search',
            headers=headers,
            json_data=request_body,
            resp_type='response'
        )

        if response.status_code == 201:
            location_header = response.headers.get('Location')
            if location_header:
                query_id_match = re.search(r'[^/]+$', location_header)
                query_id = query_id_match.group(0) if query_id_match else None
                return {"QueryID": query_id}
            else:
                raise ValueError("Location header not found in response.")
        else:
            raise ValueError(f"Unexpected response status: {response.status_code}")

    def varonis_get_query_results(self, query_id: int) -> Dict[str, Any]:
        """Fetches the results of a previously run query."""
        headers = self._headers.copy()
        return self._http_request('GET', f'/ReportAPI/api/search/{query_id}', headers=headers)


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: Optional[str]) -> int:
    """Maps Varonis severity to Cortex XSOAR severity

    Converts the Varonis alert severity level ('Low', 'Medium',
    'High') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Varonis API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    if severity is None:
        return IncidentSeverity.LOW

    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH
    }[severity]


def get_included_severitires(severity: Optional[str]) -> List[str]:
    """ Return list of severities that is equal or higher then provided

    :type severity: ``Optional[str]``
    :param severity: Severity

    :return: List of severities
    :rtype: ``List[str]``
    """
    if not severity:
        return []

    severities = ALERT_SEVERITIES.copy()

    if severity.lower() == 'medium':
        severities.remove('low')

    if severity.lower() == 'high':
        severities.remove('low')
        severities.remove('medium')

    return severities


def try_convert(item, converter, error=None):
    """Try to convert item

    :type item: ``Any``
    :param item: An item to convert

    :type converter: ``Any``
    :param converter: Converter function

    :type error: ``Any``
    :param error: Error object that will be raised in case of error convertion

    :return: A converted item or None
    :rtype: ``Any``
    """
    if item:
        try:
            return converter(item)
        except Exception:
            if error:
                raise error
            raise
    return None


def strEqual(text1: str, text2: str) -> bool:
    if not text1 and not text2:
        return True
    if not text1 or not text2:
        return False

    return text1.casefold() == text2.casefold()


def enrich_with_pagination(output: Dict[str, Any], page: int, page_size: int) -> Dict[str, Any]:
    """Enriches command output with pagination info

    :type output: ``Dict[str, Any]``
    :param output: Command output

    :type page: ``int``
    :param page: Page number

    :type page_size: ``int``
    :param page_size: Amount of elements on the page

    :return: Enriched command output
    :rtype: ``Dict[str, Any]``
    """
    output['Pagination'] = dict()
    output['Pagination']['Page'] = page
    output['Pagination']['PageSize'] = page_size
    return output


def flatten_data(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flattens the list of dictionaries into a format suitable for tableToMarkdown."""
    flattened_data = []
    for item in data:
        if isinstance(item, dict):
            flattened_item = {}
            for key, value in item.items():
                # If value is a list or dict, convert it to a string for readability
                if isinstance(value, (list, dict)):
                    flattened_item[key] = str(value)
                else:
                    flattened_item[key] = value
            flattened_data.append(flattened_item)
        elif isinstance(item, str):
            # Handle case where item is a string
            flattened_data.append({"Value": item})
        else:
            # Handle other types if necessary
            flattened_data.append({"Value": str(item)})
    return flattened_data


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed too and a
    connection to the service is successful.

    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    global TOKEN_FLAG
    message: str = ''
    if TOKEN_FLAG == True:
        message = 'ok'
    elif TOKEN_FLAG == False:
        message = 'Authorization Error: The Auth Token is null, broken, or expired. Check credentials and permissions on DSP. Ensure the ReportAPI is enabled.'
    return message


def varonis_reports_get_queries_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retrieves a list of queries and their metadata from DSP

    :type client: ''Client''
    :param client: client to use

    return: returns a table of available queries and their reports, if any
    :rtype: '''dict'''
    """

    reports_metadata = client.varonis_get_reports_metadata()
    return CommandResults(
        outputs_prefix='Varonis.Reports',
        outputs_key_field='ID',
        outputs=reports_metadata,
        readable_output=tableToMarkdown('Varonis Reports Metadata', reports_metadata)
    )


def varonis_reports_run_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Submits a query to the DSP to execute, and returns a Query ID

    :type client: ''Client''
    :param client: client to use

    :type str: '''query'''
    :param str: user-inputed query to submit to DSP

    return: API returns a json with a query location, which is parsed and returned as query_id
    :rtype: '''dict'''
    """
    query = args.get('query')
    query_result = client.varonis_run_query(query)

    if 'QueryID' in query_result:
        query_id = query_result['QueryID']
    else:
        query_id = "Query ID not found"

    return CommandResults(
        outputs_prefix='Varonis.Reports.Query',
        outputs_key_field='QueryID',
        outputs={"QueryID": query_id},
        readable_output=f'Query_ID: {query_id}'
    )


def varonis_reports_get_report_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Requests a query from the DSP to retrieve, and returns a table

    :type client: ``Client``
    :param client: client to use

    :type str: ``query_id``
    :param str: user-inputted query ID to submit to DSP

    :type bool: ``full_table``
    :param bool: whether to include empty columns in the output (default is False)

    :return: API returns a JSON with query results, if any, which is parsed, formatted, and returned as a table
    :rtype: ``dict``
    """
    query_id = args.get('query_id')
    full_table = args.get('full_table', 'false').lower() == 'true'

    query_results = client.varonis_get_query_results(query_id)
    demisto.debug(f"Full query result: {query_results}")

    search_result = query_results.get('QuerySearchResult', {})
    columns = search_result.get('Columns', [])
    items = search_result.get('Items', [])

    demisto.debug(f"Columns: {columns}")
    demisto.debug(f"Items: {items}")

    if not items:
        return CommandResults(
            readable_output="No entries.",
            outputs_prefix='Varonis.Reports.Results',
            outputs=query_results,
        )

    if full_table:
        readable_items = []
        for item in items:
            readable_item = {columns[i]: item[i] for i in range(len(columns))}
            readable_items.append(readable_item)
        readable_output = tableToMarkdown(
            f'Query Results for Query ID: {query_id}',
            readable_items
        )
    else:
        filtered_columns = []
        filtered_items = []

        for idx, column in enumerate(columns):
            if any(item[idx] for item in items):
                filtered_columns.append(column)

        for item in items:
            filtered_item = [item[idx] for idx, column in enumerate(columns) if column in filtered_columns]
            filtered_items.append(filtered_item)

        readable_items = []
        for item in filtered_items:
            readable_item = {filtered_columns[i]: item[i] for i in range(len(filtered_columns))}
            readable_items.append(readable_item)

        readable_output = tableToMarkdown(
            f'Query Results for Query ID: {query_id}',
            readable_items
        ) + '\n* Unused columns are dropped from the table to reduce whitespace. Use the full_table option for everything, including empty columns.'

    return CommandResults(
        outputs_prefix='Varonis.Reports.Results',
        outputs=query_results,
        readable_output=readable_output
    )


''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    base_url = params['url']

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        auth_url = f'{base_url}/ReportAPI/api/login'
        client.varonis_authenticate(username, password, auth_url)
        args = demisto.args()

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'varonis-reports-get-queries':
            return_results(varonis_reports_get_queries_command(client, args))

        elif demisto.command() == 'varonis-reports-run-query':
            return_results(varonis_reports_run_query_command(client, args))

        elif demisto.command() == 'varonis-reports-get-report':
            return_results(varonis_reports_get_report_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
