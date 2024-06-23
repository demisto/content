import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Callable


def parse_response(raw_data: List[Dict[str, Any]], wanted_keys: List[Any], actual_keys: List[Any]) -> \
        List[Dict[str, Any]]:
    """Lists all raw data and return outputs in Demisto's format.
    Args:
        raw_data: raw response from the api.
        wanted_keys: The keys as we would like them to be.
        actual_keys :The keys as they are in raw response.
    Returns:
        Specific Keys from the raw data.
    """

    context_list = []
    for raw in raw_data:
        context = {}
        for wanted_key, actual_key in zip(wanted_keys, actual_keys):
            if isinstance(wanted_key, list):
                inner_raw = raw.get(actual_key[0])
                if inner_raw:
                    lst_inner = []
                    for in_raw in inner_raw:
                        inner_dict = {}
                        for inner_wanted_key, inner_actual_key in zip(wanted_key[1:], actual_key[1:]):
                            inner_dict.update({inner_wanted_key: in_raw.get(inner_actual_key)})
                        lst_inner.append(inner_dict)
                    context.update({wanted_key[0]: lst_inner})
            else:
                context.update({wanted_key: raw.get(actual_key)})
        context_list.append(context)
    return context_list


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        header = {
            'X-Risk-Token': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=header)

    def http_request(self, message: str, suffix: str, params: Optional[dict] = None,
                     data: Optional[dict] = None):
        """Connects to api and Returns response.
           Args:
               message: The HTTP message, for example: GET, POST, and so on
               suffix :The API endpoint.
               params: URL parameters to specify the query.
               data:The data to send in a specific request.
           Returns:
               response from the api.
           """
        url = f'{self._base_url}{suffix}'
        try:
            response = requests.request(
                message,
                url,
                headers=self._headers,
                params=params,
                json=data,
                verify=self._verify,
            )
        except requests.exceptions.SSLError as err:
            raise DemistoException(f'Connection error in the API call to Kenna.\n'
                                   f'Check your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            raise DemistoException(f'Connection error in the API call to Kenna.\n'
                                   f'Check your Server URL parameter.\n\n{err}')
        try:
            response_dict = response.json() if response.text else {}
            if not response.ok:
                if response_dict.get('error') == "unauthorized":
                    raise DemistoException(f'Connection error in the API call to Kenna.\n'
                                           f'Check your Api Key parameter.\n\n{response_dict.get("message")}')
                else:
                    raise DemistoException(
                        f'API call to Kenna failed with error code: {response.status_code}.\n'
                        f'Error: {response_dict.get("error")}\n'
                        f'Message: {response_dict.get("message")}'
                    )
            elif response.status_code == 204:
                return {'status': 'success'}
            return response_dict
        except TypeError:
            raise Exception(f'Error in API call to Kenna, could not parse result [{response.status_code}]')


def test_module(client: Client) -> str:
    """
    Tests the connection to the Kenna v2 API by performing a basic GET request.
    """
    client.http_request('GET', '/assets')
    return 'ok'


def search_vulnerabilities(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search vulnerability command.
    Args:
        client: Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    url_suffix = '/vulnerabilities/search'
    limit: int = int(args.get('limit', 500))
    to_context = args.get('to_context')
    human_readable = []
    context: Dict[str, Any] = {}
    params = {
        'id[]': argToList(args.get('id')),
        'top_priority[]': argToList(args.get('top-priority')),
        'min_risk_meter_score': args.get('min-score'),
        'status[]': argToList(args.get('status')),
    }
    response = client.http_request(message='GET', suffix=url_suffix,
                                   params=params).get('vulnerabilities')

    if response:
        vulnerability_list = response[:limit]
        wanted_keys = ['AssetID', ['Connectors', 'DefinitionName', 'ID', 'Name', 'Vendor'], 'CveID', 'FixID',
                       'ID', 'Patch',
                       'Score', ['ScannerVulnerabilities', 'ExternalID', 'Open', 'Port'],
                       'Severity',
                       'Status', 'Threat', 'TopPriority',
                       ['ServiceTicket', 'DueDate', 'ExternalIdentifier', 'Status', 'TicketType']]
        actual_keys = ['asset_id', ['connectors', 'connector_definition_name', 'id', 'name', 'vendor'], 'cve_id',
                       'fix_id',
                       'id', 'patch', 'risk_meter_score',
                       ['scanner_vulnerabilities', 'external_unique_id', 'open', 'port'],
                       'severity', 'status', 'threat', 'top_priority',
                       ['service_ticket', 'due_date', 'external_identifier', 'status', 'ticket_type']]

        context_list = parse_response(vulnerability_list, wanted_keys, actual_keys)
        for lst in vulnerability_list:
            human_readable.append({
                'id': lst.get('id'),
                'Name': lst.get('cve_id'),
                'Score': lst.get('risk_meter_score')
            })
        context = {
            'Kenna.Vulnerabilities(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', human_readable, removeNull=True)
    else:
        human_readable_markdown = "no vulnerabilities found."

    if to_context == "False":
        return human_readable_markdown, {}, response
    return human_readable_markdown, context, response


def get_connectors(client: Client, *_) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Get Connectors command.
    Args:
        client:  Client which connects to api
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    url_suffix = '/connectors'
    human_readable = []
    context: Dict[str, Any] = {}
    connectors = client.http_request(message='GET', suffix=url_suffix).get('connectors')
    if connectors:
        wanted_keys = ['Host', 'Name', 'Running', 'ID']
        actual_keys = ['host', 'name', 'running', 'id']
        context_list = parse_response(connectors, wanted_keys, actual_keys)

        for connector in connectors:
            curr_dict = {
                'Host': connector.get('host'),
                'Name': connector.get('name'),
                'Running': connector.get('running'),
                'ID': connector.get('id')
            }
            human_readable.append(curr_dict)
        context = {
            'Kenna.ConnectorsList(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Connectors', human_readable, removeNull=True)
    else:
        human_readable_markdown = "no connectors in get response."

    return human_readable_markdown, context, connectors


def inactivate_asset(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Inactivate an asset.

    This function sends a PUT request to the '/assets/{asset_id}' endpoint with the 'inactive' field set to True.

    Args:
        client (Client): The client to use for the HTTP request.
        args (dict): A dictionary of arguments. Expected keys are 'asset_id' and optionally 'notes'.

    Returns:
        CommandResults: A CommandResults object.
    """
    asset_id = args['asset_id']
    url_suffix = f'/assets/{asset_id}'
    asset = {
        'asset': {
            'inactive': argToBoolean(args["inactive"]),
            'notes': args['notes']
        }
    }
    result = client.http_request(message='PUT', suffix=url_suffix, data=asset)
    if result.get('status') != "success":
        return CommandResults(readable_output=f'Could not inactivate asset with ID {asset_id}.', raw_response=result)
    return CommandResults(readable_output=f'Asset with ID {asset_id} was successfully inactivated.')


def get_connector_runs(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Get Connector Runs command.
    Args:
        client:  Client which connects to api
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    connector_id = str(args.get("connector_id"))
    url_suffix = f'/connectors/{connector_id}/connector_runs'
    human_readable = []
    context: Dict[str, Any] = {}
    connectors: List[Dict[str, Any]] = client.http_request(message='GET', suffix=url_suffix)
    if connectors:
        actual_keys = [
            "id", "start_time",
            "end_time", "success",
            "total_payload_count",
            "processed_palyoad_count",
            "failed_payload_count",
            "processed_assets_count",
            "assets_with_tags_reset_count",
            "processed_scanner_vuln_count",
            "updated_scanner_vuln_count",
            "created_scanner_vuln_count",
            "closed_scanner_vuln_count",
            "autoclosed_scanner_vuln_count",
            "reopened_scanner_vuln_count",
            "closed_vuln_count",
            "autoclosed_vuln_count",
            "reopened_vuln_count"
        ]
        wanted_keys = [
            "ID", "StartTime",
            "EndTime", "Success",
            "TotalPayload",
            "ProcessedPayload",
            "FailedPayload",
            "ProcessedAssets",
            "AssetsWithTagsReset",
            "ProcessedScannerVulnerabilities",
            "UpdatedScannerVulnerabilities",
            "CreatedScannerVulnerabilities",
            "ClosedScannerVulnerabilities",
            "AutoclosedScannerVulnerabilities",
            "ReopenedScannerVulnerabilities",
            "ClosedVulnerabilities",
            "AutoclosedVulnerabilities",
            "ReopenedVulnerabilities"
        ]

        context_list = parse_response(connectors, wanted_keys, actual_keys)

        for connector in connectors:
            curr_dict = {
                "ID": connector.get("id"),
                "StartTime": connector.get("start_time"),
                "EndTime": connector.get("end_time"),
                "Success": connector.get("success"),
                "TotalPayload": connector.get("total_payload_count"),
                "ProcessedPayload": connector.get("total_payload_count"),
                "FailedPayload": connector.get("failed_payload_count"),
                "ProcessedAssets": connector.get("processed_assets_count"),
                "AssetsWithTagsReset": connector.get("assets_with_tags_reset_count"),
                "ProcessedScannerVulnerabilities": connector.get("processed_scanner_vuln_count"),
                "UpdatedScannerVulnerabilities": connector.get("updated_scanner_vuln_count"),
                "CreatedScannerVulnerabilities": connector.get("created_scanner_vuln_count"),
                "ClosedScannerVulnerabilities": connector.get("closed_scanner_vuln_count"),
                "AutoclosedScannerVulnerabilities": connector.get("autoclosed_scanner_vuln_count"),
                "ReopenedScannerVulnerabilities": connector.get("reopened_scanner_vuln_count"),
                "ClosedVulnerabilities": connector.get("closed_vuln_count"),
                "AutoclosedVulnerabilities": connector.get("closed_vuln_count"),
                "ReopenedVulnerabilities": connector.get("reopened_vuln_count")
            }
            human_readable.append(curr_dict)
        context = {
            'Kenna.ConnectorRunsList(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Connector Runs', human_readable, removeNull=True)
    else:
        human_readable_markdown = "no connectors in get response."

    return human_readable_markdown, context, connectors


def run_connector(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Run Connector command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    args_id: str = str(args.get('id'))
    url_suffix = f'/connectors/{args_id}/run'
    run_response = client.http_request(message='GET', suffix=url_suffix)
    if run_response and run_response.get('success') == 'true':
        return f'Connector {args_id} ran successfully.', {}, []
    return f'Connector {args_id} did not ran successfully.', {}, []


def search_fixes(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search Fixes command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    human_readable_markdown = ''
    url_suffix = '/fixes/search'
    limit: int = int(args.get('limit', 500))
    to_context = args.get('to_context')
    context: Dict[str, Any] = {}
    params = {
        'id[]': argToList(args.get('id')),
        'top_priority[]': argToList(args.get('top-priority')),
        'min_risk_meter_score': args.get('min-score'),
        'status[]': argToList(args.get('status')),
        'per_page': limit
    }
    response = client.http_request(message='GET', suffix=url_suffix, params=params).get('fixes')
    if response:

        wanted_keys = ['ID', 'Title', ['Assets', 'ID', 'Locator', 'PrimaryLocator', 'DisplayLocator'],
                       ['Vulnerabilities', 'ID', 'ServiceTicketStatus', 'ScannerIDs'], 'CveID', 'LastUpdatedAt',
                       'Category', 'VulnerabilityCount', 'MaxScore']
        actual_keys = ['id', 'title', ['assets', 'id', 'locator', 'primary_locator', 'display_locator'],
                       ['vulnerabilities', 'id', 'service_ticket_status', 'scanner_ids'], 'cves', 'updated_at',
                       'category',
                       'vuln_count', 'max_vuln_score']
        context_list = parse_response(response, wanted_keys, actual_keys)

        remove_html = re.compile(r'<[^>]+>')
        for fix in response:
            if fix:
                human_readable_markdown += str(fix.get('title')) + '\n'
                human_readable_markdown += '#### ID: ' + str(fix.get('id')) + '\n'
                human_readable_markdown += str(fix.get('vuln_count')) + ' vulnerabilities affected\n'
                human_readable_markdown += '#### Diagnosis:\n'
                human_readable_markdown += remove_html.sub(' ', str(fix.get('diagnosis'))) + '\n' + '&nbsp;' + '\n'
        context = {
            'Kenna.Fixes(val.ID === obj.ID)': context_list
        }
    else:
        human_readable_markdown = "no fixes in response."
    if to_context == "False":
        return human_readable_markdown, {}, response
    return human_readable_markdown, context, response


def update_asset_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Update an asset in the Kenna Security Platform.

    Args:
        client (Client): The Kenna client object.
        args (dict[str, str]): A dictionary containing:
            - asset ID (required)
            - notes (required)
            - inactive (optional)

    Returns:
        CommandResults: If the update is successful,the result will contain a success message.
        If the update fails, the result will contain an error message.
    """
    asset_id = args['id']
    url_suffix = f'/assets/{asset_id}'
    asset = {
        'asset': {
            'notes': args['notes']
        }
    }
    if inactive := args.get("inactive"):
        asset['asset'].update({'inactive': argToBoolean(inactive)})

    result = client.http_request(message='PUT', suffix=url_suffix, data=asset)
    if result.get('status') != "success":
        return CommandResults(readable_output=f'Could not update asset with ID {asset_id}.', raw_response=result)
    return CommandResults(readable_output=f'Asset with ID {asset_id} was successfully updated.')


def update_vulnerability(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Update Vulnerabilities command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    params_to_update: dict = {
        'vulnerability': {}
    }
    args_id = str(args.get('id'))
    status = str(args.get('status'))
    notes = str(args.get('notes'))
    if notes:
        params_to_update['vulnerability'].update({'notes': notes})
    if status:
        params_to_update['vulnerability'].update({'status': status})
    url_suffix = f'/vulnerabilities/{args_id}'
    result = client.http_request(message='PUT', suffix=url_suffix, data=params_to_update)

    if result.get('status') != "success":
        return 'Could not update asset.', {}, []
    return f'Asset {args_id} was updated', {}, []


def search_assets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Search for assets in Kenna based on the provided parameters.

    Args:
        client (Client): The Kenna client object.
        args (dict[str, Any]): A dictionary of arguments provided by the user.
            The optional arguments are:
            - 'limit': The maximum number of assets to return. Default is 500.
            - 'to_context': Whether to include the results in the context. Default is True.
            - 'hostname': The hostname to search for. Default is an empty string.
            - 'tags': A list of tags to search for. Default is an empty list.
            - 'id': A list of asset IDs to search for. Default is an empty list.
            - 'min-score': The minimum vulnerability score for which to return vulnerabilities. Default is None.

    Returns:
        CommandResults: A CommandResults object containing the results of the search.

    """
    url_suffix = '/assets/search'
    limit = arg_to_number(args.get('limit')) or 500
    to_context = argToBoolean(args.get('to_context', True))
    hostname: str = args.get('hostname', '')
    tags = argToList(args.get('tags'))

    hostname_query = f'hostname:({hostname.replace(",", " ")})' if hostname else hostname

    params = {
        'id[]': argToList(args.get('id')),
        'q': hostname_query,
        'min_risk_meter_score': args.get('min-score'),
        'tags[]': tags
    }
    response = client.http_request(message='GET', suffix=url_suffix, params=params).get('assets')
    if not response:
        return CommandResults(readable_output="No assets were found.", raw_response=response)

    assets = response[:limit]
    if len(assets) > limit:
        demisto.debug(f"found {len(assets)} assets, using the limit arg to keep only the first {limit} ones")

    wanted_keys = ['ID', 'Hostname', 'Score', 'IpAddress', 'VulnerabilitiesCount', 'OperatingSystem', 'Tags',
                   'Fqdn', 'Status', 'Owner', 'Priority', 'Notes', 'OperatingSystem', 'ExternalID']
    actual_keys = ['id', 'hostname', 'risk_meter_score', 'ip_address', 'vulnerabilities_count',
                   'operating_system', 'tags', 'fqdn', 'status', 'owner', 'priority', 'notes', 'operating_system',
                   'external_id']
    context: list[dict[str, Any]] = parse_response(assets, wanted_keys, actual_keys)
    human_readable = []
    for lst in assets:
        human_readable.append({
            'id': lst.get('id'),
            'Hostname': lst.get('hostname'),
            'IP-address': lst.get('ip_address'),
            'Vulnerabilities Count': args.get('vulnerabilities_count'),
            'Operating System': lst.get('operating_system'),
            'Score': lst.get('risk_meter_score')
        })

    return CommandResults(
        outputs_prefix="Kenna.Assets",
        outputs_key_field="ID",
        readable_output=tableToMarkdown('Kenna Assets', human_readable, removeNull=True),
        outputs=context if to_context else None,
        raw_response=response
    )


def get_asset_vulnerabilities(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Get Asset by Vulnerability command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    args_id = str(args.get('id'))
    limit: int = int(args.get('limit', 500))
    to_context = args.get('to_context')
    url_suffix = f'/assets/{args_id}/vulnerabilities'
    human_readable = []
    context: Dict[str, Any] = {}

    response = client.http_request(message='GET', suffix=url_suffix).get(
        'vulnerabilities')
    if response:
        vulnerabilities_list = response[:limit]
        wanted_keys: List[Any] = ['AssetID', 'CveID', 'ID', 'Patch', 'Status', 'TopPriority', 'Score']
        actual_keys: List[Any] = ['asset_id', 'cve_id', 'id', 'patch', 'status', 'top_priority', 'risk_meter_score']
        context_list: List[Dict[str, Any]] = parse_response(vulnerabilities_list, wanted_keys, actual_keys)

        for lst in vulnerabilities_list:
            human_readable.append({
                'id': lst.get('id'),
                'Name': lst.get('cve_id'),
                'Score': lst.get('risk_meter_score')
            })
        context = {
            'Kenna.VulnerabilitiesOfAsset(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', human_readable, removeNull=True)
    else:
        human_readable_markdown = "no vulnerabilities in response"
    if to_context == "False":
        return human_readable_markdown, {}, response
    return human_readable_markdown, context, response


def add_tags(client: Client, args: dict) -> tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Add tags command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    asset_id = args.get('id')
    tags = args.get('tag')
    url_suffix = f'/assets/{asset_id}/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    result = client.http_request(message='PUT', suffix=url_suffix, data=asset)

    if result.get('status') != "success":
        return f'Tag {tags} was not added to asset {asset_id}.', {}, []
    return f'Tag {tags} was added to asset {asset_id}.', {}, []


def delete_tags(client: Client, args: dict) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """Delete tags command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    asset_id = args.get('id')
    tags = args.get('tag')
    url_suffix = f'/assets/{asset_id}/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    result = client.http_request(message='DELETE', suffix=url_suffix, data=asset)
    if result.get('status') != "success":
        return f'Tag {tags} was not deleted from asset {asset_id}.', {}, []
    return f'Tag {tags} was successfully deleted from asset {asset_id}.', {}, []


def search_assets_by_external_id_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Search for assets by their external ID.

    This function sends a GET request to the '/assets/search' endpoint with the external ID as a query parameter.
    If 'to_context' is True, it returns the results in the context.

    Args:
        client (Client): The client to use for the HTTP request.
        args (dict): A dictionary of arguments. Expected keys are 'external_id' (required), 'limit', and 'to_context'.

    Returns:
        CommandResults: A CommandResults object.
    """

    external_id = args['external_id']
    limit: int = arg_to_number(args.get('limit')) or 500
    to_context = argToBoolean(args.get('to_context', False))
    url_suffix = f'/assets/search?&q=external_id%3A{external_id}/'
    human_readable = []
    response = client.http_request(message='GET', suffix=url_suffix).get('assets')

    if not response:
        return CommandResults(readable_output="No assets were found.", raw_response=response)

    assets = response[:limit]
    if len(assets) > limit:
        demisto.debug(f"found {len(assets)} assets, using the limit arg to keep only the first {limit} ones.")

    wanted_keys = ['ID', 'Hostname', 'Score', 'IpAddress', 'VulnerabilitiesCount',
                   'OperatingSystem', 'Tags', 'Fqdn', 'Status', 'Owner', 'Priority', 'Notes', 'OperatingSystem']
    actual_keys = ['id', 'hostname', 'risk_meter_score', 'ip_address', 'vulnerabilities_count',
                   'operating_system', 'tags', 'fqdn', 'status', 'owner', 'priority', 'notes', 'operating_system']
    context: list[dict[str, Any]] = parse_response(assets, wanted_keys, actual_keys)
    for lst in assets:
        human_readable.append({
            'id': lst.get('id'),
            'Hostname': lst.get('hostname'),
            'IP-address': lst.get('ip_address'),
            'Vulnerabilities Count': args.get('vulnerabilities_count'),
            'Operating System': lst.get('operating_system'),
            'Score': lst.get('risk_meter_score')
        })

    return CommandResults(
        outputs_prefix="Kenna.Assets",
        outputs_key_field="ID",
        readable_output=tableToMarkdown('Kenna Assets', human_readable, removeNull=True),
        outputs=context if to_context else None,
        raw_response=response
    )


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    api = params.get('credentials_key', {}).get('password') or params.get('key')
    if not api:
        raise DemistoException('Kenna API key must be provided.')
    # Service base URL
    base_url = params.get('url', '')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)
    # Should we use system proxy settings
    use_proxy = params.get('proxy', False)
    # Initialize Client object
    client = Client(base_url=base_url, api_key=api, verify=use_ssl, proxy=use_proxy)

    demisto.debug(f'Command being called is {command}')

    commands: dict[str, Callable[[Client, dict[str, str]], tuple[str, dict[Any, Any], list[Any]]]] = {
        'kenna-search-vulnerabilities': search_vulnerabilities,
        'kenna-get-connectors': get_connectors,
        'kenna-run-connector': run_connector,
        'kenna-search-fixes': search_fixes,
        'kenna-update-vulnerability': update_vulnerability,
        'kenna-get-asset-vulnerabilities': get_asset_vulnerabilities,
        'kenna-add-tag': add_tags,
        'kenna-delete-tag': delete_tags,
        'kenna-get-connector-runs': get_connector_runs
    }
    try:
        if command in commands:
            return_outputs(*commands[command](client, args))
        elif command == "test-module":
            return_results(test_module(client))
        elif command == "kenna-update-asset":
            return_results(update_asset_command(client, args))
        elif command == "kenna-search-assets":
            return_results(search_assets_command(client, args))
        elif command == "kenna-search-assets-by-external-id":
            return_results(search_assets_by_external_id_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as err:
        return_error(f"Failed to execute {command} command.\nError:\n{err!s}")


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
