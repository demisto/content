from typing import Any, Callable, Dict, List, Optional, Tuple

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from CommonServerPython import BaseClient

# Disable insecure warnings
urllib3.disable_warnings()


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
                     data: Optional[dict] = None):  # -> Dict[str, Any]
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
            response_list = response.json() if response.text else {}
            if not response.ok:
                if response_list.get('error') == "unauthorized":
                    raise DemistoException(f'Connection error in the API call to Kenna.\n'
                                           f'Check your Api Key parameter.\n\n{demisto.get(response_list, "error.message")}')
                else:
                    raise DemistoException(f'API call to Kenna failed ,Error code [{response.status_code}]'
                                           f' - {demisto.get(response_list, "error.message")}')
            elif response.status_code == 204:
                return {'status': 'success'}
            return response_list
        except TypeError:
            raise Exception(f'Error in API call to Kenna, could not parse result [{response.status_code}]')


def test_module(client: Client, *_):
    """
    Performs basic get request from Kenna v2
    """
    res_vulnerabilities = client.http_request('GET', '/vulnerabilities')
    res_assets = client.http_request('GET', '/assets')

    if isinstance(res_vulnerabilities.get('vulnerabilities'), list) and isinstance(res_assets.get('assets'), list):
        return 'ok', None, None
    raise Exception('Error occurred while trying to query the api.')


def search_vulnerabilities(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
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
        'id': argToList(args.get('id')),
        'top_priority': argToList(args.get('top-priority')),
        'min_risk_meter_score': args.get('min-score'),
        'status': argToList(args.get('status')),
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


def get_connectors(client: Client, *_) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
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


def get_connector_runs(client: Client, *_) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Get Connector Runs command.
    Args:
        client:  Client which connects to api
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    connector_id = demisto.getArg("connector_id")
    url_suffix = '/connectors/%s/connector_runs' % connector_id
    human_readable = []
    context: Dict[str, Any] = {}
    connectors: List[Dict[str, Any]] = client.http_request(message='GET', suffix=url_suffix)
    if connectors:
        keys = [
            "id", "start_time",
            "end_time", "success",
            "total_payload_count",
            "processed_palyoad_count",
            "failed_payload_count",
            "processed_assets_count",
            "assets_with_tags_reset_count",
            "processed_scanner_vuln_count",
            "created_scanner_vuln_count",
            "closed_scanner_vuln_count",
            "autoclosed_scanner_vuln_count",
            "reopened_scanner_vuln_count",
            "closed_vuln_count",
            "autoclosed_vuln_count",
            "reopened_vuln_count"
        ]

        context_list = parse_response(connectors, keys, keys)

        for connector in connectors:
            curr_dict = {
                "id": connector.get("id"),
                "start_time": connector.get("start_time"),
                "end_time": connector.get("end_time"),
                "success": connector.get("success"),
                "total_payload_count": connector.get("total_payload_count"),
                "processed_payload_count": connector.get("total_payload_count"),
                "failed_payload_count": connector.get("failed_payload_count"),
                "processed_assets_count": connector.get("processed_assets_count"),
                "assets_with_tags_reset_count": connector.get("assets_with_tags_reset_count"),
                "processed_scanner_vuln_count": connector.get("processed_scanner_vuln_count"),
                "updated_scanner_vuln_count": connector.get("updated_scanner_vuln_count"),
                "created_scanner_vuln_count": connector.get("created_scanner_vuln_count"),
                "closed_scanner_vuln_count": connector.get("closed_scanner_vuln_count"),
                "autoclosed_scanner_vuln_count": connector.get("autoclosed_scanner_vuln_count"),
                "reopened_scanner_vuln_count": connector.get("reopened_scanner_vuln_count"),
                "closed_vuln_count": connector.get("closed_vuln_count"),
                "autoclosed_vuln_count": connector.get("closed_vuln_count"),
                "reopened_vuln_count": connector.get("reopened_vuln_count")
            }
            human_readable.append(curr_dict)
        context = {
            'Kenna.ConnectorRunsList(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Connector Runs', human_readable, removeNull=True)
    else:
        human_readable_markdown = "no connectors in get response."

    return human_readable_markdown, context, connectors


def run_connector(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
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


def search_fixes(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
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
        'id': argToList(args.get('id')),
        'top_priority': argToList(args.get('top-priority')),
        'min_risk_meter_score': args.get('min-score'),
        'status': argToList(args.get('status')),
    }
    response = client.http_request(message='GET', suffix=url_suffix, params=params).get('fixes')
    if response:
        fixes_list = response[:limit]

        wanted_keys = ['ID', 'Title', ['Assets', 'ID', 'Locator', 'PrimaryLocator', 'DisplayLocator'],
                       ['Vulnerabilities', 'ID', 'ServiceTicketStatus', 'ScannerIDs'], 'CveID', 'LastUpdatedAt',
                       'Category', 'VulnerabilityCount', 'MaxScore']
        actual_keys = ['id', 'title', ['assets', 'id', 'locator', 'primary_locator', 'display_locator'],
                       ['vulnerabilities', 'id', 'service_ticket_status', 'scanner_ids'], 'cves', 'updated_at',
                       'category',
                       'vuln_count', 'max_vuln_score']
        context_list = parse_response(fixes_list, wanted_keys, actual_keys)

        remove_html = re.compile(r'<[^>]+>')
        for fix in fixes_list:
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


def update_asset(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Update Asset command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """

    args_id = str(args.get('id'))
    url_suffix = f'/assets/{args_id}'
    asset = {
        'asset': {
            'notes': args.get('notes')
        }
    }
    result = client.http_request(message='PUT', suffix=url_suffix, data=asset)
    try:
        if result.get('status') != "success":
            return 'Could not update asset.', {}, []
        return f'Asset {args_id} was updated', {}, []
    except DemistoException as err:
        return f'Error occurred while preforming update-asset command {err}', {}, []


def update_vulnerability(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
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
    try:
        if result.get('status') != "success":
            return 'Could not update asset.', {}, []
        return f'Asset {args_id} was updated', {}, []
    except DemistoException as err:
        return f'Error occurred while preforming update-vulenrability command {err}', {}, []


def search_assets(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search Asset command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    url_suffix = '/assets/search'
    human_readable = []
    limit: int = int(args.get('limit', 500))
    to_context = args.get('to_context')
    context: Dict[str, Any] = {}
    if args.get('tags'):
        tags = argToList(args.get('tags'))
    else:
        tags = args.get('tags')
    params = {
        'id': argToList(args.get('id')),
        'hostname': argToList(args.get('hostname')),
        'min_risk_meter_score': args.get('min-score'),
        'tags': tags
    }
    response = client.http_request(message='GET', suffix=url_suffix, params=params).get(
        'assets')
    if response:
        assets_list = response[:limit]
        wanted_keys = ['ID', 'Hostname', 'Score', 'IpAddress', 'VulnerabilitiesCount', 'OperatingSystem', 'Tags',
                       'Fqdn', 'Status', 'Owner', 'Priority', 'Notes', 'OperatingSystem']
        actual_keys = ['id', 'hostname', 'risk_meter_score', 'ip_address', 'vulnerabilities_count',
                       'operating_system',
                       'tags', 'fqdn', 'status', 'owner', 'priority', 'notes', 'operating_system']
        context_list: List[Dict[str, Any]] = parse_response(assets_list, wanted_keys, actual_keys)

        for lst in assets_list:
            human_readable.append({
                'id': lst.get('id'),
                'Hostname': lst.get('hostname'),
                'IP-address': lst.get('ip_address'),
                'Vulnerabilities Count': args.get('vulnerabilities_count'),
                'Operating System': lst.get('operating_system'),
                'Score': lst.get('risk_meter_score')
            })
        context = {
            'Kenna.Assets(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Assets', human_readable, removeNull=True)
    else:
        human_readable_markdown = "no assets in response"
    if to_context == "False":
        return human_readable_markdown, {}, response
    return human_readable_markdown, context, response


def get_asset_vulnerabilities(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
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


def add_tags(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Add tags command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    args_id = str(args.get('id'))
    tags = str(args.get('tag'))
    url_suffix = f'/assets/{args_id}/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    result = client.http_request(message='PUT', suffix=url_suffix, data=asset)
    try:
        if result.get('status') != "success":
            return f'Tag {tags} was not added to asset {args_id}', {}, []
        return f'Tag {tags} was added to asset {args_id}', {}, []
    except DemistoException as err:
        return f'Error occurred while preforming add-tags command {err}', {}, []


def delete_tags(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Delete tags command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    args_id = str(args.get('id'))
    tags = str(args.get('tag'))
    url_suffix = f'/assets/{args_id}/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    result = client.http_request(message='DELETE', suffix=url_suffix, data=asset)
    try:
        if result.get('status') != "success":
            return f'Tag {tags} was not deleted to asset {args_id}', {}, []
        return f'Tag {tags} was deleted to asset {args_id}', {}, []
    except DemistoException as err:
        return f'Error occurred while preforming delete-tags command {err}', {}, []


def main():
    params = demisto.params()
    api = params.get('key')
    # Service base URL
    base_url = params.get('url')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)
    # Should we use system proxy settings
    use_proxy = params.get('proxy') == 'true'
    # Initialize Client object
    client = Client(base_url=base_url, api_key=api, verify=use_ssl, proxy=use_proxy)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    # Commands dict
    commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], List[Any]]]] = {
        'test-module': test_module,
        'kenna-search-vulnerabilities': search_vulnerabilities,
        'kenna-get-connectors': get_connectors,
        'kenna-run-connector': run_connector,
        'kenna-search-fixes': search_fixes,
        'kenna-update-asset': update_asset,
        'kenna-update-vulnerability': update_vulnerability,
        'kenna-search-assets': search_assets,
        'kenna-get-asset-vulnerabilities': get_asset_vulnerabilities,
        'kenna-add-tag': add_tags,
        'kenna-delete-tag': delete_tags,
        'kenna-get-connector-runs': get_connector_runs
    }

    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'{command} is not an existing Kenna v2 command')

    except Exception as err:
        return_error(f'Error from Kenna v2 Integration \n\n {err} \n', err)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
