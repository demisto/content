from json import JSONDecodeError

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Optional
import urllib3
import json
from distutils.util import strtobool

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

def test_module(client: Client, *_):
    """
    Performs basic get request to get item samples1
    """
    res_vulnerabilities = client._http_request('GET', '/vulnerabilities')
    res_assets = client._http_request('GET', '/assets')

    if isinstance(res_vulnerabilities.get('vulnerabilities'), list) and isinstance(res_assets.get('assets'), list):
        return 'ok', None, None
    else:
        raise Exception('Error occurred while trying to query the api.')


# ----------------------------------------------- Auxiliary functions -------------------------------------------------


def connect_api(client: Client, message: str, suffix: str, params: dict = None, data: dict = None) -> dict:
    """A wrapper for requests lib to send our requests and handle requests and responses better.

    :type client: ``Client``
    :param client: The HTTP method, for example: GET, POST, and so on.

     :type suffix: ``str``
     :param suffix: The API endpoint.

     :return: Depends on the resp_type parameter
     :rtype: ``dict``
     """

    raw_response = client._http_request(message, suffix, params=params, json_data=data)
    # Check if response contains errors
    if raw_response.get('errors'):
        return DemistoException(raw_response.get('errors'))
    elif raw_response.get('error'):
        return DemistoException(raw_response.get('error'))
    response_list = raw_response
    return response_list


# list of dict of keys where the key is the wanted name and the value is the actual name
def create_dict(raw_data: dict, wanted_keys: list, actual_keys: list, unique_wanted_keys: list = None,
                unique_actual_keys: list = None):
    context_list = []
    for raw in raw_data:
        context = {}
        for i in range(len(wanted_keys)):
            wanted_key = wanted_keys[i]
            actual_key = actual_keys[i]
            if isinstance(wanted_key, list):
                list_wanted_key = wanted_keys[i][0]
                list_actual_key = actual_keys[i][0]
                inner_raw = raw.get(list_actual_key)
                if inner_raw:
                    inner_wanted_keys = wanted_keys[i][1:]
                    inner_actual_keys = actual_keys[i][1:]
                    inner_dict = {}
                    lst_inner = []
                    for in_raw in inner_raw:
                        for j in range(len(inner_wanted_keys)):
                            inner_dict.update({inner_wanted_keys[j]: in_raw.get(inner_actual_keys[j])})
                        lst_inner.append(inner_dict)
                    context.update({list_wanted_key: lst_inner})
            else:
                context.update({wanted_key: raw.get(actual_key)})
        if unique_wanted_keys:
            for i in range(len(unique_wanted_keys)):
                unique_actual_key = unique_actual_keys[i]
                unique_wanted_key = unique_wanted_keys[i]
                inner_unique_actual_keys = unique_actual_keys[i][1:]
                inner_unique_wanted_keys = unique_wanted_keys[i][1:]
                inner_dict = {}
                lst_inner = []
                key = unique_actual_key[0]
                raw_unique = raw.get(key)
                if (raw_unique):
                    for j in range(len(inner_unique_wanted_keys)):
                        inner_dict.update({inner_unique_wanted_keys[j]: raw_unique.get(inner_unique_actual_keys[j])})
                    context.update({unique_wanted_key: inner_dict})
        context_list.append(context)
    return context_list


# ----------------------------------------- Commands Functions ---------------------------------------------------------


def search_vulnerabilities(client: Client, args: dict) -> (str, dict, dict):
    url_suffix = '/vulnerabilities/search'
    hreadable = []
    params = {
        'id' + '[]': args.get('id'),
        'top_priority' + '[]': args.get('top-priority'),
        'min_risk_meter_score': args.get('min-score'),
        'status' + '[]': args.get('status')
    }
    vulnerability_list = connect_api(client=client, message='GET', suffix=url_suffix, params=params).get(
        'vulnerabilities')

    wanted_keys = ['AssetID', ['Connectors', 'DefinitionName', 'ID', 'Name', 'Vendor'], 'CveID', 'FixID', 'ID', 'Patch',
                   'RiskMeterScore', ['ScannerVulnerabilities', 'ExternalID', 'Open', 'Port'], 'Score', 'Severity',
                   'Status', 'Threat', 'TopPriority']
    actual_keys = ['asset_id', ['connectors', 'connector_definition_name', 'id', 'name', 'vendor'], 'cve_id', 'fix_id',
                   'id', 'patch', 'lisk_meter_score', ['scanner_vulnerabilities', 'external_unique_id', 'open', 'port'],
                   'score', 'severity', 'status', 'threat', 'top_priority']
    unique_wanted_keys = [['ServiceTicket', 'DueDate', 'ExternalIdentifier', 'Status', 'TicketType']]
    unique_actual_keys = [['service_ticket', 'due_date', 'external_identifier', 'status', 'ticket_type']]
    context_list = create_dict(vulnerability_list, wanted_keys, actual_keys, unique_wanted_keys, unique_actual_keys)

    for lst in vulnerability_list:
        hreadable.append({
            'id': lst.get('id'),
            'Name': lst.get('cve_id'),
            'Score': lst.get('risk_meter_score')
        })
    context = {
        'Kenna': context_list
    }
    h_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', hreadable)
    return h_readable_markdown, context, vulnerability_list


def get_connectors(client: Client, args: dict) -> (str, dict, dict):
    url_suffix = '/connectors'
    hreadable = []
    connectors = connect_api(client=client, message='GET', suffix=url_suffix).get('connectors')

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
        hreadable.append(curr_dict)
    context = {
        'Kenna.ConnectorsList(val.ID === obj.ID)': context_list
    }
    h_readable_markdown = tableToMarkdown('Kenna Connectors', hreadable)
    return h_readable_markdown, context, connectors


def run_connector(client: Client, args: dict) -> (str, dict, dict):
    args_id = args.get('id')
    url_suffix = '/connectors/' + args_id + '/run'
    run_response = connect_api(client=client, message='GET', suffix=url_suffix)
    if run_response.success == 'true':
        return 'Connector ran successfully!', None, None
    else:
        return 'Connector did not run successfully!', None, None


def search_fixes(client: Client, args: dict) -> (str, dict, dict):

    hreadable = ''
    fixes_list = []
    url_suffix = '/fixes/search'
    params = {
        'id' + '[]': args.get('id'),
        'top_priority' + '[]': args.get('top-priority'),
        'min_risk_meter_score': args.get('min-score'),
        'status' + '[]': args.get('status'),
    }
    response = connect_api(client=client, message='GET', suffix=url_suffix, params=params)
    if response.get('fix'):
        fixes_list = [response.get('fix')]
    elif response.get('fixes'):
        fixes_list = response.get('fixes')

    wanted_keys = ['ID', 'Title', ['Assets', 'ID', 'Locator', 'PrimaryLocator', 'DisplayLocator'],
                   ['Vulnerabilities', 'ID', 'ServiceTicketStatus', 'ScannerIDs'], 'CveID', 'LastUpdatedAt',
                   'Category', 'VulnerabilityCount', 'MaxScore']
    actual_keys = ['id', 'title', ['assets', 'id', 'locator', 'primary_locator', 'display_locator'],
                   ['vulnerabilities', 'id', 'service_ticket_status', 'scanner_ids'], 'cves', 'updated_at', 'category',
                   'vuln_count', 'max_vuln_score']
    context_list = create_dict(fixes_list, wanted_keys, actual_keys)


    remove_html = re.compile(r'<[^>]+>')
    for fix in fixes_list:
        hreadable += fix.get('title') + '\n'
        hreadable += '#### ID: ' + str(fix.get('id')) + '\n'
        hreadable += str(fix.get('vuln_count')) + ' vulnerabilities affected\n'
        hreadable += '#### Diagnosis:\n'
        hreadable += remove_html.sub(' ', fix.get('diagnosis')) + '\n' + '&nbsp;' + '\n'
    context = {
        'Kenna.Fixes(val.ID === obj.ID)': context_list
    }
    return hreadable, context, response

def update_asset(client: Client, args: dict) -> (str, dict, dict):
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
        if type(exp.__context__) == (JSONDecodeError):
            return 'Asset ' + str(args_id) + ' was updated', None, None
        else:
            return 'Could not update asset.', None, None


def update_vulnerability(client: Client, args: dict) -> (str, dict, dict):
    update = {
        'vulnerability': {}
    }
    args_id = str(args.get('id'))
    status = args.get('status')
    notes = args.get('notes')
    if notes:
        update.get('vulnerability').update({'notes': notes})
    if status:
        update.get('vulnerability').update({'status': status})
    url_suffix = '/vulnerabilities/' + args_id
    try:
        connect_api(client=client, message='PUT', suffix=url_suffix, data=update)
    except DemistoException as exp:
        if type(exp.__context__) == (JSONDecodeError):
            return 'Asset ' + str(args_id) + ' was updated', None, None
        else:
            return 'Could not update asset.', None, None


def search_assets(client: Client, args: dict) -> (str, dict, dict):
    url_suffix = '/assets/search'
    hreadable = []
    params = {
        'id' + '[]': args.get('id'),
        'hostname' + '[]': args.get('hostname'),
        'min_risk_meter_score': args.get('min-score'),
        'ip_address' + '[]': args.get('ip-address'),
        'tags' + '[]': args.get('tags')
    }
    assets_list = connect_api(client=client, message='GET', suffix=url_suffix, params=params).get('assets')

    wanted_keys = ['ID', 'Hostname', 'MinScore', 'IpAddress', 'VulnerabilitiesCount', 'OperatingSystem', 'Tags',
                   'Fqdn', 'Status', 'Owner', 'Priority','Notes']
    actual_keys = ['id', 'hostname', 'min_risk_meter_score', 'ip_address', 'vulnerabilities_count', 'operating_system',
                   'tags', 'fqdn', 'status', 'owner', 'priority','notes']
    context_list = create_dict(assets_list, wanted_keys, actual_keys)

    for lst in assets_list:
        hreadable.append({
            'id': lst.get('id'),
            'Hostname': lst.get('hostname'),
            'IP-address': lst.get('ip_address'),
            'Vulnerabilities Count': args.get('vulnerabilities_count')
        })
    context = {
        'Kenna.Assets(val.ID === obj.ID)': context_list
    }
    h_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', hreadable)
    return h_readable_markdown, context, assets_list

def get_asset_vulenrabilities(client: Client, args: dict) -> (str, dict, dict):
    id = args.get('id')
    url_suffix = '/assets/' + id + '/vulnerabilities'
    hreadable = []

    vulnerabilities_list = connect_api(client=client, message='GET', suffix=url_suffix).get('vulnerabilities')

    wanted_keys = ['AssetID',  'CveID', 'ID', 'Patch',  'Status',  'TopPriority']
    actual_keys = ['asset_id',  'cve_id','id', 'patch', 'status',  'top_priority']
    context_list = create_dict(vulnerabilities_list, wanted_keys, actual_keys)

    for lst in vulnerabilities_list:
        hreadable.append({
            'id': lst.get('id'),
            'Name': lst.get('cve_id'),
            'Score': lst.get('risk_meter_score')
        })
    context = {
        'Kenna.VulnerabilitiesOfAsset(val.ID === obj.ID)': context_list
    }
    h_readable_markdown = tableToMarkdown('Kenna Vulnerabilities', hreadable)
    return h_readable_markdown, context, vulnerabilities_list

def add_tags(client: Client, args: dict) -> (str, dict, dict):
    args_id = str(args.get('id'))
    tags = args.get('tag')
    url_suffix = '/assets/' + args_id + '/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    try:
        connect_api(client=client, message='PUT', suffix=url_suffix, data=asset)
    except DemistoException as exp:
        if type(exp.__context__) == (JSONDecodeError):
            return 'Tag ' + str(tags) + ' was added to asset '+args_id, None, None
        else:
            return 'Tag ' + str(tags) + ' was not added to asset '+args_id, None, None


def delete_tags(client: Client, args: dict) -> (str, dict, dict):
    args_id = str(args.get('id'))
    tags = args.get('tag')
    url_suffix = '/assets/' + args_id + '/tags'
    asset = {
        'asset': {
            'tags': tags
        }
    }
    try:
        connect_api(client=client, message='DELETE', suffix=url_suffix, data=asset)
    except DemistoException as exp:
        if type(exp.__context__) == (JSONDecodeError):
            return 'Tag ' + str(tags) + ' was deleted to asset '+args_id, None, None
        else:
            return 'Tag ' + str(tags) + ' was not deleted to asset '+args_id, None, None


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
    command = demisto.command()  # demisto run command with this url
    LOG(f'Command being called is {command}')
    # Commands dict
    commands = {
        'test-module': test_module,
        'kenna-search-vulnerabilities': search_vulnerabilities,
        'kenna-get-connectors': get_connectors,
        'kenna-run-connector': run_connector,
        'kenna-search-fixes': search_fixes,
        'kenna-update-asset': update_asset,
        'kenna-update-vulnerability': update_vulnerability,
        'kenna-search-assets': search_assets,
        'kenna-get-asset-vulnerabilities': get_asset_vulenrabilities,
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
