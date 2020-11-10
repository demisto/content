from typing import List, Tuple, Dict, Any, Optional, Callable

import urllib3
import demistomock as demisto
from CommonServerPython import *

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
                     data: Optional[dict] = None) -> Dict[str, Any]:

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
        'id[]': argToList(args.get('id')),
        'hostname[]': argToList(args.get('hostname')),
        'min_risk_meter_score': args.get('min-score'),
        'tags[]': tags
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


def get_asset_group(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Search Asset Group command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    args_id = str(args.get('id'))

    url_suffix = f'/asset_groups/{args_id}'
    human_readable_markdown = ''

    response = client.http_request(message='GET', suffix=url_suffix).get('asset_group')

    if response:
        context = {
            'Kenna.AssetGroup':{
                'ID': int(response.get('id')),
                'Name': str(response.get('name')),
                'QueryString': str(response.get('querystring')),
                'createdAt': str(response.get('created_at')),
                'UpdatedAt': str(response.get('updated_at')),
                'RiskMeterScore': int(response.get('risk_meter_score')),
                'TrueRiskMeterScore': int(response.get('true_risk_meter_score')),
                'AssetCount': int(response.get('asset_count')),
                'VulnerabilityCount': int(response.get('vulnerability_count')),
                'FixCount': int(response.get('fix_count')),
                'TopPriorityCount': int(response.get('top_priority_count')),
                'ActiveInternetBreachesCount': int(response.get('active_internet_breaches_count')),
                'EasilyExploitableCount': int(response.get('easily_exploitable_count')),
                'MalwareExploitableCount': int(response.get('malware_exploitable_count')),
                'PopularTargetsCount': int(response.get('popular_targets_count')),
                'UniqueOpenCVECount': int(response.get('unique_open_cve_count')),
                'PredictedExploitableCount': int(response.get('predicted_exploitable_count'))
            }
        }

        human_readable_markdown += 'Name: ' + str(response.get('name')) + '\n'
        human_readable_markdown += 'ID: ' + str(response.get('id')) + '\n'
        human_readable_markdown += 'Asset Count: ' + str(response.get('asset_count')) + '\n'
        human_readable_markdown += 'Risk Meter Score: ' + str(response.get('risk_meter_score')) + '\n'
        human_readable_markdown += 'Vulnerability Count: ' + str(response.get('vulnerability_count')) + '\n'
        human_readable_markdown += 'Fix Count: ' + str(response.get('fix_count')) + '\n'
        human_readable_markdown += 'Active Internet Breaches Count: ' + str(response.get('active_internet_breaches_count')) + '\n'

    else:
        human_readable_markdown = "Group not found."
    return human_readable_markdown, context, response


def list_asset_groups(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Lists Asset Groups command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    human_readable_markdown = ''
    url_suffix = '/asset_groups?per_page=1000'

    response = client.http_request(message='GET', suffix=url_suffix).get('asset_groups')

    if response:
        wanted_keys = ['ID', 'Name', 'RiskMeterScore', 'AssetCount', 'FixCount']
        actual_keys = ['id', 'name', 'risk_meter_score', 'asset_count','fix_count']
        context_list = parse_response(response, wanted_keys, actual_keys)
        context = {
            'Kenna.AssetGroups(val.ID === obj.ID)': context_list
        }
        human_readable_markdown = tableToMarkdown('Asset Groups', context_list, headers=['Name','ID','RiskMeterScore', 'AssetCount', 'FixCount'])
    else:
        human_readable_markdown = "no groups in response."
    return human_readable_markdown, context, response


def get_top_fixes(client: Client, args: dict) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Gets Top Fixes command.
    Args:
        client:  Client which connects to api
        args: arguments for the request
    Returns:
        Human Readable
        Entry Context
        Raw Data
    """
    args_id = str(args.get('id'))

    url_suffix = f'/asset_groups/{args_id}/top_fixes'
    human_readable_markdown = ''

    response = client.http_request(message='GET', suffix=url_suffix).get('asset_group')

    if response:

        asset_group = response
        topfix_groups = asset_group.get('top_fixes')

        context_topfixes = []
        for topfix in topfix_groups:
            cur_topfix = {}
            cur_topfix['FixGroupNumber'] = topfix.get('fix_group_number')
            cur_topfix['RiskScoreReduction'] = topfix.get('risk_score_reduction')
            cur_topfix['Fixes'] = []

            for fix in topfix.get('fixes'):
                cur_fix= {}
                cur_fix['ID'] = fix.get('id')
                cur_fix['Title'] = fix.get('title')
                cur_fix['Diagnosis'] = fix.get('diagnosis')
                cur_fix['Solution'] = fix.get('solution')
                cur_fix['Category'] = fix.get('category')
                cur_fix['Consequence'] = fix.get('consequence')

                assets = []
                for asset in fix.get('assets'):
                    cur_asset = {}
                    cur_asset['ID'] = asset.get('id')
                    cur_asset['Hostname'] = asset.get('hostname')
                    cur_asset['IP_Address'] = asset.get('ip_address')
                    cur_asset['Operating_System'] = asset.get('operating_system')
                    assets.append(cur_asset)

                cur_fix['Assets'] = assets
                cur_topfix['Fixes'].append(cur_fix)
            context_topfixes.append(cur_topfix)

        context = {
            'Kenna.AssetGroup.TopFixes': context_topfixes
        }


        # human readable section
        human_readable = []
        human_readable_markdown += 'Group Name: ' + str(asset_group.get('name')) + '\n'
        human_readable_markdown += 'Group ID: ' + str(asset_group.get('id')) + '\n'
        human_readable_markdown += 'Current Risk Meter Score: ' + str(asset_group.get('risk_meter_score')) + '\n'


        for topfix in topfix_groups:
            fix_titles = ''
            asset_count = ''
            for fix in topfix.get('fixes'):
                fix_titles += str('* ' + fix.get('title') + '\n')
                asset_count += str(len(fix.get('assets')))  + '\n'

            curr_dict = {
                'Fix Score Reduction': topfix.get('risk_score_reduction'),
                'Assets Involved': asset_count,
                'Fixes': fix_titles
            }
            human_readable.append(curr_dict)

        human_readable_markdown +=  tableToMarkdown('Top Fixes', human_readable, headers=['Fix Score Reduction','Assets Involved', 'Fixes'])

    else:
        human_readable_markdown = "Group not found."
    return human_readable_markdown, context, response


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
        'kenna-get-asset-group': get_asset_group,
        'kenna-list-asset-groups': list_asset_groups,
        'kenna-get-top-fixes': get_top_fixes,
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
