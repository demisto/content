import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MODULE_NAME_BREACHES = "breaches"

MAPPING: dict = {
    MODULE_NAME_BREACHES: {
        "date":
            "uploadTime",
        "name":
            "email",
        "prefix":
            "Data Breach"
    }
}

# API Client params
TIMEOUT = 60.
RETRIES = 4
STATUS_LIST_TO_RETRY = [429, 500]

STATUS_CODE_MSGS = {
    401: "Bad Credentials",
    403: "Forbidden. Something is wrong with your account, please, contact to Resecurity.",
    404: "Not found. There is no such data on server.",
    500: "There are some troubles on server with your request."
}

DEFAULT_RESULTS_SIZE_LIMIT = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_MODE = 2  # last results

PAGINATION_HEADER_NAME = 'X-Pagination-Page-Count'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def check_connection(self) -> Dict[str, Any]:
        """
        Check connection '/monitor/check-connection' API endpoint
        """
        return self._http_request(
            method='GET',
            url_suffix='/monitor/check-connection',
        )

    def get_task_monitor_results(self, monitor_task_id, module_name: str, page, page_size, mode) -> requests.Response:
        """
        Get monitor task results by module '/monitor/task-results-by-module' API endpoint
        """
        response = self._http_request(
            method="GET",
            url_suffix='/monitor/task-results-by-module',
            resp_type='response',
            params={
                'id': monitor_task_id,
                'module_name': module_name,
                'page': page,
                'per-page': page_size,
                'mode': mode
            },
            timeout=TIMEOUT, retries=RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY
        )

        # check response status
        if response.status_code != 200:
            if response.status_code in STATUS_CODE_MSGS:
                raise DemistoException(STATUS_CODE_MSGS[response.status_code])
            else:
                raise DemistoException(
                    f"Status code {response.status_code} for API request"
                )

        return response


''' HELPER FUNCTIONS '''


def get_human_readable_output(module_name, monitor_task_id, result):
    return tableToMarkdown(name="{0} results from task with ID {1}".format(module_name, monitor_task_id),
                           t=result, removeNull=True, date_fields=['detection_date'])


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        result = client.check_connection()
        if result.get('message') == 'ok':
            return 'ok'
        else:
            raise DemistoException("Failed to establish connection with provided credentials.")
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_task_monitor_results_command(module_name: str):
    """_summary_

    Args:
        module_name (str): _description_
    """
    def get_task_monitor_results(client: Client, args: Dict) -> CommandResults:

        # get params from user
        monitor_task_id = arg_to_number(args.get("monitor_task_id"), 'monitor_task_id', True)
        limit = arg_to_number(args.get("limit", DEFAULT_RESULTS_SIZE_LIMIT))
        page = arg_to_number(args.get("page"))
        page_size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE))
        mode = arg_to_number(args.get("mode", DEFAULT_MODE))

        if page is not None:
            # request data from specific page
            response = client.get_task_monitor_results(monitor_task_id, module_name, page, page_size, mode)

            result = response.json()
        else:
            # request data from many pages
            page = 1

            # limit 'page size' value if it is bigger that 'limit' value
            if limit is not None and page_size is not None and page_size > limit:
                page_size = limit
            result_count = 0

            result = []
            while limit is not None and result_count < limit:
                response = client.get_task_monitor_results(monitor_task_id, module_name, page, page_size, mode)

                total_pages = response.headers.get(PAGINATION_HEADER_NAME)
                if not total_pages:
                    demisto.debug(total_pages)
                    raise DemistoException(
                        f"Something is wrong, header {PAGINATION_HEADER_NAME} is empty for API request"
                    )
                total_pages = int(total_pages)

                result += response.json()
                result_count = len(result)
                page += 1

                if page > total_pages:
                    break

        # compose result data
        return CommandResults(
            outputs_prefix=f"Resecurity.{MAPPING.get(module_name, {}).get('prefix', '').replace(' ', '')}",
            outputs_key_field="id",
            outputs=result[:limit],
            readable_output=get_human_readable_output(MAPPING.get(module_name, {}).get("prefix"), monitor_task_id, result),
            raw_response=result,
            ignore_auto_extract=True
        )

    return get_task_monitor_results


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get API key
    api_key = params.get('credentials', {}).get('password')

    # get the service API URL
    base_url = urljoin(params['url'], '/api')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # Add the proper headers for authentication
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(api_key, ''),
            headers=headers,
            proxy=proxy)

        # command cases implementation
        commands = {
            "resecurity-get-task-monitor-results-data-breaches": get_task_monitor_results_command(MODULE_NAME_BREACHES)
        }

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
