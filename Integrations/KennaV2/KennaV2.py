from json import JSONDecodeError
from typing import List, Tuple, Dict, Any, Optional, Callable

from CommonServerPython import *
import urllib3
import demistomock as demisto

# Disable insecure warnings
urllib3.disable_warnings()


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
        return super()._http_request(message, suffix, params=params, json_data=data)


def test_module(client: Client, *_):
    """
    Performs basic get request to get item samples12
    """
    res_vulnerabilities = client._http_request('GET', '/vulnerabilities')
    res_assets = client._http_request('GET', '/assets')

    if isinstance(res_vulnerabilities.get('vulnerabilities'), list) and isinstance(res_assets.get('assets'), list):
        return 'ok', None, None
    else:
        raise Exception('Error occurred while trying to query the api.')


# ----------------------------------------------- Auxiliary functions -------------------------------------------------


def connect_api(client: Client, message: str, suffix: str, params: Optional[dict] = None,
                data: Optional[dict] = None) -> Dict[str, Any]:
    """Connects to api and Returns response.
    Args:
        client:  BaseClient which connects to api
        message: The HTTP message, for example: GET, POST, and so on
        suffix :The API endpoint.
        params: URL parameters to specify the query.
        data:The data to send in a specific request.
    Returns:
        response from the api.
    """
    raw_response = client.http_request(message, suffix, params=params, data=data)
    # Check if response contains errors
    if raw_response.get('errors'):
        raise DemistoException(raw_response.get('errors'))
    elif raw_response.get('error'):
        raise DemistoException(raw_response.get('error'))
    response_list = raw_response
    return response_list


def create_dict(raw_data: List[Dict[str, Any]], wanted_keys: List[Any], actual_keys: List[Any]) -> List[Dict[str, Any]]:
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
                    inner_dict = {}
                    lst_inner = []
                    for in_raw in inner_raw:
                        for inner_wanted_key, inner_actual_key in zip(wanted_key[1:], actual_key[1:]):
                            inner_dict.update({inner_wanted_key: in_raw.get(inner_actual_key)})
                        lst_inner.append(inner_dict)
                    context.update({wanted_key[0]: lst_inner})
            else:
                context.update({wanted_key: raw.get(actual_key)})
        context_list.append(context)
    return context_list


# ----------------------------------------- Commands Functions ---------------------------------------------------------


def search_vulnerabilities(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search vulnerability command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    url_suffix = '/vulnerabilities/search'
    human_readable = []
    context = {}
    params = {
        'id' + '[]': args.get('id'),
        'top_priority' + '[]': args.get('top-priority'),
        'min_risk_meter_score': args.get('min-score'),
        'status' + '[]': args.get('status')
    }
    vulnerability_list = connect_api(client=client, message='GET', suffix=url_suffix,
                                     params=params).get('vulnerabilities')
    if vulnerability_list:
        wanted_keys = ['AssetID', ['Connectors', 'DefinitionName', 'ID', 'Name', 'Vendor'], 'CveID', 'FixID',
                       'ID', 'Patch',
                       'RiskMeterScore', ['ScannerVulnerabilities', 'ExternalID', 'Open', 'Port'], 'Score',
                       'Severity',
                       'Status', 'Threat', 'TopPriority',
                       ['ServiceTicket', 'DueDate', 'ExternalIdentifier', 'Status', 'TicketType']]
        actual_keys = ['asset_id', ['connectors', 'connector_definition_name', 'id', 'name', 'vendor'], 'cve_id',
                       'fix_id',
                       'id', 'patch', 'lisk_meter_score',
                       ['scanner_vulnerabilities', 'external_unique_id', 'open', 'port'],
                       'score', 'severity', 'status', 'threat', 'top_priority',
                       ['service_ticket', 'due_date', 'external_identifier', 'status', 'ticket_type']]

        context_list = create_dict(vulnerability_list, wanted_keys, actual_keys)
        for lst in vulnerability_list:
            human_readable.append({
                'id': lst.get('id'),
                'Name': lst.get('cve_id'),
                'Score': lst.get('risk_meter_score')
            })
        context = {
            'Kenna.Vulnerabilities(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', human_readable)
    else:
        human_readable_markdown = "no vulnerabilities found"
    return human_readable_markdown, context, vulnerability_list


def get_connectors(client: Client, *_) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Get Connectors command.
    Args:
        client:  BaseClient which connects to api
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    url_suffix = '/connectors'
    human_readable = []
    context = {}
    connectors = connect_api(client=client, message='GET', suffix=url_suffix).get('connectors')
    if connectors:
        wanted_keys = ['Host', 'Name', 'Running', 'ID']
        actual_keys = ['host', 'name', 'running', 'id']
        context_list = create_dict(connectors, wanted_keys, actual_keys)

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
        human_readable_markdown = tableToMarkdown('Kenna Connectors', human_readable)
    else:
        human_readable_markdown = "no connectors in get response"

    return human_readable_markdown, context, connectors


def run_connector(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Run Connector command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    args_id: str = str(args.get('id'))
    url_suffix = '/connectors/' + args_id + '/run'
    run_response = connect_api(client=client, message='GET', suffix=url_suffix)
    if run_response:
        if run_response.get('success') == 'true':
            return 'Connector ran successfully!', {}, []
        else:
            return 'Connector did not run successfully!', {}, []
    else:
        return "error from response", {}, []


def search_fixes(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search Fixes command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    human_readable_markdown = ''
    url_suffix = '/fixes/search'
    context = {}
    params = {
        'id' + '[]': args.get('id'),
        'top_priority' + '[]': args.get('top-priority'),
        'min_risk_meter_score': args.get('min-score'),
        'status' + '[]': args.get('status'),
    }
    fixes_list = connect_api(client=client, message='GET', suffix=url_suffix, params=params).get('fixes')
    if fixes_list:
        wanted_keys = ['ID', 'Title', ['Assets', 'ID', 'Locator', 'PrimaryLocator', 'DisplayLocator'],
                       ['Vulnerabilities', 'ID', 'ServiceTicketStatus', 'ScannerIDs'], 'CveID', 'LastUpdatedAt',
                       'Category', 'VulnerabilityCount', 'MaxScore']
        actual_keys = ['id', 'title', ['assets', 'id', 'locator', 'primary_locator', 'display_locator'],
                       ['vulnerabilities', 'id', 'service_ticket_status', 'scanner_ids'], 'cves', 'updated_at',
                       'category',
                       'vuln_count', 'max_vuln_score']
        context_list = create_dict(fixes_list, wanted_keys, actual_keys)

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
        human_readable_markdown = "no fixes in response"
    return human_readable_markdown, context, fixes_list


def update_asset(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Update Asset command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """

    args_id = str(args.get('id'))
    url_suffix = '/assets/' + args_id
    asset = {
        'asset': {
            'notes': args.get('notes')
        }
    }
    try:
        connect_api(client=client, message='PUT', suffix=url_suffix, data=asset)
    except DemistoException as exp:
        if type(exp.__context__) == JSONDecodeError:
            return 'Asset ' + str(args_id) + ' was updated', {}, []
        else:
            return 'Could not update asset.', {}, []
    return 'error', {}, []


def update_vulnerability(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Update Vulnerabilities command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    params_to_update: dict = {}
    args_id = str(args.get('id'))
    status = str(args.get('status'))
    notes = str(args.get('notes'))
    if notes:
        params_to_update['vulnerability'].update({'notes': notes})
    if status:
        params_to_update['vulnerability'].update({'status': status})
    url_suffix = '/vulnerabilities/' + args_id
    try:
        connect_api(client=client, message='PUT', suffix=url_suffix, data=params_to_update)
    except DemistoException as exp:
        if type(exp.__context__) == JSONDecodeError:
            return 'Asset ' + str(args_id) + ' was updated', {}, []
        else:
            return 'Could not update asset.', {}, []
    return 'error', {}, []


def search_assets(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search Asset command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    url_suffix = '/assets/search'
    human_readable = []
    context = {}
    params = {
        'id' + '[]': args.get('id'),
        'hostname' + '[]': args.get('hostname'),
        'min_risk_meter_score': args.get('min-score'),
        'ip_address' + '[]': args.get('ip-address'),
        'tags' + '[]': args.get('tags')
    }
    assets_list = connect_api(client=client, message='GET', suffix=url_suffix, params=params).get(
        'assets')
    if assets_list:
        wanted_keys = ['ID', 'Hostname', 'MinScore', 'IpAddress', 'VulnerabilitiesCount', 'OperatingSystem', 'Tags',
                       'Fqdn', 'Status', 'Owner', 'Priority', 'Notes']
        actual_keys = ['id', 'hostname', 'min_risk_meter_score', 'ip_address', 'vulnerabilities_count',
                       'operating_system',
                       'tags', 'fqdn', 'status', 'owner', 'priority', 'notes']
        context_list: List[Dict[str, Any]] = create_dict(assets_list, wanted_keys, actual_keys)

        for lst in assets_list:
            human_readable.append({
                'id': lst.get('id'),
                'Hostname': lst.get('hostname'),
                'IP-address': lst.get('ip_address'),
                'Vulnerabilities Count': args.get('vulnerabilities_count')
            })
        context = {
            'Kenna.Assets(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', human_readable)
    else:
        human_readable_markdown = "no assets in response"
    return human_readable_markdown, context, assets_list


def get_asset_vulnerabilities(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Get Asset by Vulnerability command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    args_id = str(args.get('id'))
    url_suffix = '/assets/' + args_id + '/vulnerabilities'
    human_readable = []
    context = {}

    vulnerabilities_list = connect_api(client=client, message='GET', suffix=url_suffix).get(
        'vulnerabilities')
    if vulnerabilities_list:
        wanted_keys: List[Any] = ['AssetID', 'CveID', 'ID', 'Patch', 'Status', 'TopPriority']
        actual_keys: List[Any] = ['asset_id', 'cve_id', 'id', 'patch', 'status', 'top_priority']
        context_list: List[Dict[str, Any]] = create_dict(vulnerabilities_list, wanted_keys, actual_keys)

        for lst in vulnerabilities_list:
            human_readable.append({
                'id': lst.get('id'),
                'Name': lst.get('cve_id'),
                'Score': lst.get('risk_meter_score')
            })
        context = {
            'Kenna.VulnerabilitiesOfAsset(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', human_readable)
    else:
        human_readable_markdown = "no vulnerabilities in response"
    return human_readable_markdown, context, vulnerabilities_list


def add_tags(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Add tags command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    args_id = str(args.get('id'))
    tags = str(args.get('tag'))
    url_suffix = '/assets/' + args_id + '/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    try:
        connect_api(client=client, message='PUT', suffix=url_suffix, data=asset)
    except DemistoException as exp:
        if type(exp.__context__) == JSONDecodeError:
            return 'Tag ' + tags + ' was added to asset ' + args_id, {}, []
        else:
            return 'Tag ' + tags + ' was not added to asset ' + args_id, {}, []
    return 'error', {}, []


def delete_tags(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Delete tags command.
    Args:
        client:  BaseClient which connects to api
        args: arguments for the request
    Returns:
        Success/ Failure , according to the response
    """
    args_id = str(args.get('id'))
    tags = str(args.get('tag'))
    url_suffix = '/assets/' + args_id + '/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    try:
        connect_api(client=client, message='DELETE', suffix=url_suffix, data=asset)
    except DemistoException as exp:
        if type(exp.__context__) == JSONDecodeError:
            return 'Tag ' + str(tags) + ' was deleted to asset ' + args_id, {}, []
        else:
            return 'Tag ' + str(tags) + ' was not deleted to asset ' + args_id, {}, []
    return 'error', {}, []


# -------------------------------------------- Main Function -----------------------------------------------------------


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
    }

    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError

    except Exception as e:
        return_error(f'Error from Example Integration {e}', e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
