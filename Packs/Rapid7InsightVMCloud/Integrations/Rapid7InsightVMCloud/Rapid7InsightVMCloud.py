import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""IMPORTS"""



import urllib3
from requests import Response

# Disable insecure warnings
urllib3.disable_warnings()


""" Globals Values """

INTEGRATION_NAME = 'Rapid7InsightVMCloud'
INTEGRATION_COMMAND_NAME = 'insightvm-cloud'
INTEGRATION_CONTEXT_NAME = 'Rapid7InsightVMCloud'

"""CLIENT-CLASS"""


class Client(BaseClient):
    def make_request(
        self,
        method: str,
        url_suffix: str,
        params: dict | None = None,
        data: dict | None = None,
        json_data: dict | None = None,
        timeout: float = 10,
        resp_type: str = "json",
    ) -> Response | dict:
        """
            Performs API request to the specified endpoint and reutrns the full Response object

        Args:
            method (str) required: The HTTP method, for example, GET, POST, and so on.
            url_suffix (str) required: The API endpoint.
            params (dict): URL parameters to specify the query. Default is None.
            data (dict): The data to send in a 'POST' request. Default is None.
            json_data (dict): The dictionary to send in a 'POST' request. Default is None.
            timeout: (float): Time (in seconds) for the client to wait to establish a connection before a timeout occurs.
                                Default is 10.
            resp_type (str): Determines which data format to return from the HTTP request. Other options are 'text',
                             'content', 'xml' or 'response'. Use 'response' to return the full response object.
                             Default is json.

        Returns:
            Either a Response Object or Dictionary, depending on the resp_type value
        """
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            data=data,
            json_data=json_data,
            timeout=timeout,
            resp_type=resp_type,
        )


""" COMMAND FUNCTIONS """


def test_module_command(client: Client, *_) -> str:
    """
        Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client (Client Object): Client object with request.
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """

    method: str = "GET"
    url_suffix: str = "/admin/health"

    try:
        response: Response | dict = client.make_request(method=method, url_suffix=url_suffix, resp_type="response")
        if isinstance(response, Response) and response.status_code == 200:
            return "ok"
        raise DemistoException(f"Test module failed, {response}")
    except Exception as e:
        raise DemistoException(f"Error:, {e}")


def get_health_check_command(client: Client) -> dict:  # type: ignore
    """
    Endpoints to monitor service health and quality.

    Args:
        client: object to use

    """

    method = 'GET'
    endpoint = "/admin/health"
    response = client.make_request(method=method, url_suffix=endpoint)
    if response:
        return response  # type: ignore
    else:
        return_error('no response')


def get_asset_command(client: Client, asset_id: str) -> dict:  # type: ignore
    """
    Returns the assessment and details of an asset (specified by id).

    Args:
        client (Client Object): Client object with request.
        asset_id(str) : The identifier of the asset to retrieve the details for.

    """

    method = "GET"
    endpoint = f"/v4/integration/assets/{asset_id}"
    response = client.make_request(
        method=method,
        url_suffix=endpoint
    )
    if response:
        return response  # type: ignore
    else:
        return_error('no response')


def search_assets_command(client: Client, hostname: None, page: str, size: str) -> CommandResults:  # type: ignore
    """
    Returns the inventory, assessment, and summary details for a page of assets.

    Args:
        client (Client Object): Client object with request.
        hostname: Search criteria for filtering assets returned.
        page: The index of the page (zero-based) to retrieve
        size: The number of records per page to retrieve.

    """
    params = {
        "page": page,
        "size": size
    }
    method = "POST"
    endpoint = "/v4/integration/assets"
    assets = f"asset.name CONTAINS '{hostname}'"
    data = {
        "asset": f"{assets}"

    }
    response = client.make_request(
        method=method,
        url_suffix=endpoint,
        json_data=data,
        params=params
    )
    if response:
        response_data = response.get("data")  # type: ignore
        markdown = tableToMarkdown(
            'This is required Asset data',
            response_data
        )
        result = CommandResults(
            readable_output=markdown,
            outputs_prefix='Rapid7.InsighVMCloud.Assets',
            outputs_key_field='id',
            outputs=response_data
        )
        return result
    else:
        return_error('no response')


def get_scan_command(client: Client, scan_id=str) -> CommandResults:  # type: ignore
    """
    Retrieves the scan with the specified identifier.

    Args:
        client (Client Object): Client object with request.
        scan_id : The identifier of the scan.

    """

    endpoint = f"/v4/integration/scan/{scan_id}"
    method = 'GET'
    response = client.make_request(
        method=method,
        url_suffix=endpoint
    )
    if response:
        response_data = response
        markdown = tableToMarkdown(
            'This is the Required Scan Information',
            response_data
        )
        result = CommandResults(
            readable_output=markdown,
            outputs_prefix='Rapid7.InsighVMCloud.Scans',
            outputs_key_field='id',
            outputs=response_data
        )
        return result
    else:
        return_error('no response')


def get_scan_engines_command(client: Client, page: int, size: int) -> CommandResults:  # type: ignore
    """
    Retrieves a page of scan engines.

    Args:
        client (Client Object): Client object with request.
        page: The index of the page (zero-based) to retrieve
        size: The number of records per page to retrieve.

    """

    method = "GET"
    params = {
        "page": page,
        "size": size
    }
    endpoint = "/v4/integration/scan/engine"
    if int(size) > 500:
        return_error("You're over the maximum size limit(500), please choose a lower size value")
    else:
        response = client.make_request(
            method=method,
            url_suffix=endpoint,
            params=params
        )
        if response:
            response_data = response.get("data")  # type: ignore
            markdown = tableToMarkdown(
                'This is Required Scan Information',
                response_data
            )
            result = CommandResults(
                readable_output=markdown,
                outputs_prefix='Rapid7.InsighVMCloud.Engines',
                outputs_key_field='id',
                outputs=response_data
            )
            return result
        else:
            return_error('no response')


def start_scan_command(client: Client, asset_id: str, name: str) -> CommandResults:  # type: ignore
    """
    Starts a scan.

    Args:
        client (Client Object): Client object with request.
        asset_id : The identifiers of the assets to scan.
        name : The name of the scan.

    """

    args = demisto.args()
    assets_id = args.get("asset_id")
    list_id = assets_id.split(',')
    method = "POST"
    endpoint = "/v4/integration/scan"
    data = {
        "asset_ids": list_id,
        "name": name
    }

    response = client.make_request(
        method=method,
        url_suffix=endpoint,
        json_data=data
    )
    if response:
        scan_response = response.get("scans")  # type: ignore
        markdown = tableToMarkdown(
            'This is required Scan Result',
            scan_response
        )

        result = CommandResults(
            readable_output=markdown,
            outputs_prefix='Rapid7.InsighVMCloud.Scans',
            outputs_key_field='id',
            outputs=scan_response
        )
        return result
    else:
        return_error('no response')


def last_sites_command(client: Client, page: int, size=int) -> CommandResults:  # type: ignore
    """
    Returns the details for sites.

    Args:
        client (Client Object): Client object with request.
        page: The index of the page (zero-based) to retrieve
        size: The number of records per page to retrieve.

    """

    params = {
        "page": page,
        "size": size
    }

    if int(size) > 500:
        return_error("Exceed size limit")

    else:
        method = "POST"
        endpoint = "/v4/integration/sites"
        headers = ["name", "type"]
        response = client.make_request(
            method=method,
            url_suffix=endpoint,
            params=params
        )
        if response:
            res = response.get("data")  # type: ignore
            markdown = tableToMarkdown('List Sites', res, headers)
            result = CommandResults(
                readable_output=markdown,
                outputs_prefix='Rapid7.InsighVMCloud.Sites',
                outputs_key_field='name',
                outputs=response
            )
            return result
        else:
            return_error("no response")


def search_vulnerabilities_command(client: Client, query: str, page: int, size=int) -> dict:  # type: ignore
    """
    Returns all vulnerabilities that can be assessed.

    Args:
        client (Client Object): Client object with request.
        query: query to search vulnerabilities.
        page: The index of the page (zero-based) to retrieve
        size: The number of records per page to retrieve.

    """

    query = query
    params = {
        "page": page,
        "size": size
    }
    if int(size) > 500:
        return_error("Exceed size limit")
    else:
        method = "POST"
        endpoint = "/v4/integration/vulnerabilities"
        data = {
            "vulnerability": query
        }
        response = client.make_request(
            method=method,
            url_suffix=endpoint,
            json_data=data,
            params=params
        )

        if response:
            return response  # type: ignore
        else:
            return_error('no response')


def stop_scan_command(client: Client, id: str) -> CommandResults:
    """
    Stops the scan with the specified identifier.

    Args:
        client (Client Object): Client object with request.
        id: The identifier of the stop scan.

    """
    method = "POST"
    endpoint = f"/v4/integration/scan/{id}/stop"
    try:
        response: Response | dict = client.make_request(method=method, url_suffix=endpoint, resp_type="response")
        if isinstance(response, Response) and response.status_code == 202:
            command_results = CommandResults(readable_output='Scan Stop successfully.')
            return command_results
        raise DemistoException(f"Scan failed, {response}")
    except Exception as e:
        raise DemistoException(f"Error:, {e}")


def main():
    # Storing and processing required parameters
    params = demisto.params()
    base_url = params.get('base_url')
    token = params.get('credentials').get('password')
    headers = {
        'X-Api-Key': f'{token}',
        'Content-Type': 'application/json'
    }
    verify_ssl = not params.get('insecure', False)
    proxy = params.get("proxy") == "false"
    # Initializing the Client Object with required configuration
    client = Client(
        base_url=base_url,
        verify=verify_ssl,
        proxy=proxy,
        headers=headers
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-health-check': get_health_check_command,
        f'{INTEGRATION_COMMAND_NAME}-get-asset': get_asset_command,
        f'{INTEGRATION_COMMAND_NAME}-get-scan': get_scan_command,
        f'{INTEGRATION_COMMAND_NAME}-get-scan-engines': get_scan_engines_command,
        f'{INTEGRATION_COMMAND_NAME}-search-assets': search_assets_command,
        f'{INTEGRATION_COMMAND_NAME}-last-sites': last_sites_command,
        f'{INTEGRATION_COMMAND_NAME}-search-vulnerabilities': search_vulnerabilities_command,
        f'{INTEGRATION_COMMAND_NAME}-start-scan': start_scan_command,
        f'{INTEGRATION_COMMAND_NAME}-stop-scan': stop_scan_command
    }
    try:
        if command in commands:
            results = commands[command](client=client, **demisto.args())  # type: ignore
            return_results(results)

        else:
            raise NotImplementedError(f"{command} is not an existing Rapid7InsightVMCloud command")

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
