import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_CONTEXT_NAME = 'ImpervaWAF'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    session_id = ''

    def do_request(self, method, url_suffix, json_data=None):
        if not self.session_id:
            self.login()

        res = self._http_request(method, f'SecureSphere/api/v1/{url_suffix}', json_data=json_data,
                                 headers={'Cookie': self.session_id}, ok_codes=(200, 401, 406), resp_type='response')
        if res.status_code == 401:
            self.login()
            res = self._http_request(method, f'SecureSphere/api/v1/{url_suffix}', json_data=json_data,
                                     headers={'Cookie': self.session_id}, ok_codes=(200, 401, 406),
                                     resp_type='response')
        if res.text:
            res = res.json()
        else:
            res = {}
        extract_errors(res)
        return res

    def login(self):
        res = self._http_request('POST', 'SecureSphere/api/v1/auth/session', auth=self._auth)
        extract_errors(res)
        self.session_id = res.get('session-id')

    def get_ip_group_entities(self, group_name, table_name):
        raw_res = self.do_request('GET', f'conf/ipGroups/{group_name}')
        entries = []
        for entry in raw_res.get('entries'):
            entries.append({'Type': entry.get('type'),
                            'IpAddressFrom': entry.get('ipAddressFrom'),
                            'IpAddressTo': entry.get('ipAddressTo'),
                            'NetworkAddress': entry.get('networkAddress'),
                            'CidrMask': entry.get('cidrMask')})

        human_readable = tableToMarkdown(table_name, entries, removeNull=True,
                                         headers=['Type', 'IpAddressFrom', 'IpAddressTo', 'NetworkAddress', 'CidrMask'])
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}.IpGroup(val.Name===obj.Name)':
                         {'Name': group_name, 'Entries': entries}}

        return human_readable, entry_context, raw_res

    def get_custom_policy_outputs(self, policy_name, table_name):
        raw_res = self.do_request('GET', f'conf/policies/security/webServiceCustomPolicies/{policy_name}')
        policy = {'Name': policy_name,
                  'Enabled': raw_res.get('enabled'),
                  'OneAlertPerSession': raw_res.get('oneAlertPerSession'),
                  'DisplayResponsePage': raw_res.get('displayResponsePage'),
                  'Severity': raw_res.get('severity'),
                  'Action': raw_res.get('action'),
                  'FollowedAction': raw_res.get('followedAction'),
                  'ApplyTo': raw_res.get('applyTo'),
                  'MatchCriteria': raw_res.get('matchCriteria')}

        hr_policy = policy.copy()
        del hr_policy['MatchCriteria']
        del hr_policy['ApplyTo']
        human_readable = tableToMarkdown(table_name, hr_policy, removeNull=True)

        if raw_res.get('applyTo'):
            human_readable += '\n\n' + tableToMarkdown('Services to apply the policy to', raw_res.get('applyTo'),
                                                       removeNull=True)

        for match in raw_res.get('matchCriteria', []):
            tmp_match = match.copy()
            operation = match['operation']
            match_type = match['type']

            # generate human readable for sourceIpAddresses type
            if match_type == 'sourceIpAddresses':
                if tmp_match.get('userDefined'):
                    for i, element in enumerate(tmp_match['userDefined']):
                        tmp_match['userDefined'][i] = {'IP Address': tmp_match['userDefined'][i]}
                    human_readable += '\n\n' + tableToMarkdown(f'Match operation: {operation}\n Source IP addresses:',
                                                               tmp_match['userDefined'], removeNull=True)

                if tmp_match.get('ipGroups'):
                    for i, element in enumerate(tmp_match['ipGroups']):
                        tmp_match['ipGroups'][i] = {'Group name': tmp_match['ipGroups'][i]}
                    human_readable += '\n\n' + tableToMarkdown(f'Match operation: {operation}\n IP Groups:',
                                                               tmp_match['ipGroups'], removeNull=True)

            # generate human readable for sourceGeolocation type
            elif match_type == 'sourceGeolocation':
                if tmp_match.get('values'):
                    for i, element in enumerate(tmp_match['values']):
                        tmp_match['values'][i] = {'Country name': tmp_match['values'][i]}
                    human_readable += '\n\n' + tableToMarkdown(f'Match operation: {operation}\n Countries to match:',
                                                               tmp_match['values'], removeNull=True)

        entry_context = {f'{INTEGRATION_CONTEXT_NAME}.CustomWebPolicy(val.Name===obj.Name)': policy}
        return human_readable, entry_context, raw_res


def extract_errors(res):
    if not isinstance(res, list) and res.get('errors'):
        error_message = ''
        for err in res['errors']:
            error_message += f'error-code: {err.get("error-code")}, description: {err.get("description")}'
        raise Exception(error_message)


def generate_policy_data_body(args):
    severity = args.get('severity')
    action = args.get('action')
    followed_action = args.get('followed-action')

    body = {}

    if args.get('enabled'):
        body['enabled'] = args['enabled'] == 'True'
    if args.get('one-alert-per-session'):
        body['oneAlertPerSession'] = args['one-alert-per-session'] == 'True'
    if args.get('display-response-page'):
        body['displayResponsePage'] = args['display-response-page'] == 'True'

    if severity:
        body['severity'] = severity
    if action:
        body['action'] = action
    if followed_action:
        body['followedAction'] = followed_action

    return body


def generate_match_criteria(body, args):
    geo_location_criteria_operation = args.get('geo-location-criteria-operation')
    ip_addresses_criteria_operation = args.get('ip-addresses-criteria-operation')

    ip_groups = args.get('ip-groups', '')
    ip_addreses = args.get('ip-addresses', '')
    country_names = args.get('country-names', '')
    match_criteria = []

    if geo_location_criteria_operation:
        if not country_names:
            raise Exception('country-names argument is empty')

        geo_location_match_item = {'type': 'sourceGeolocation',
                                   'operation': geo_location_criteria_operation,
                                   'values': country_names.split(',')}
        match_criteria.append(geo_location_match_item)

    if ip_addresses_criteria_operation:
        if not ip_groups and not ip_addreses:
            raise Exception('ip-groups and ip-addresses arguments are empty, please fill at least one of them')

        ip_addresses_match_item = {'type': 'sourceIpAddresses',
                                   'operation': ip_addresses_criteria_operation}
        if ip_groups:
            ip_addresses_match_item['ipGroups'] = ip_groups.split(',')
        if ip_addreses:
            ip_addresses_match_item['userDefined'] = ip_addreses.split(',')

        match_criteria.append(ip_addresses_match_item)

    body['matchCriteria'] = match_criteria
    return body


def generate_ip_groups_entries(args):
    entry_type = args.get('entry-type')
    ip_from = args.get('ip-address-from')
    ip_to = args.get('ip-address-to')
    network_address = args.get('network-address')
    cidr_mask = args.get('cidr-mask')
    operation = args.get('operation')
    json_entries = args.get('json-entries')

    if not json_entries:
        entry = {}
        if entry_type == 'single':
            entry['ipAddressFrom'] = ip_from
        elif entry_type == 'range':
            entry['ipAddressFrom'] = ip_from
            entry['ipAddressTo'] = ip_to
        elif entry_type == 'network':
            entry['networkAddress'] = network_address
            entry['cidrMask'] = cidr_mask
        else:
            raise Exception('entry-type argument is invalid')
        entry['type'] = entry_type
        entry['operation'] = operation
        body = {'entries': [entry]}
    else:
        try:
            json_entries = json.loads(json_entries)
        except Exception:
            raise Exception(f'Failed to parse json-entries as JSON data,  received object:\n{json_entries}')
        body = {'entries': json_entries}
    return body


@logger
def test_module(client, args):
    raw_res = client.do_request('GET', 'conf/sites')
    if raw_res.get('sites'):
        demisto.results('ok')


@logger
def ip_group_list_command(client, args):
    raw_res = client.do_request('GET', 'conf/ipGroups')
    groups = []
    if raw_res.get('names'):
        groups = raw_res['names']
        for i, element in enumerate(groups):
            groups[i] = {'Name': groups[i]}

    human_readable = tableToMarkdown('IP groups', groups, removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.IpGroup(val.Name===obj.Name)': groups}
    return_outputs(human_readable, entry_context, raw_res)


@logger
def ip_group_list_entries_command(client, args):
    group_name = args.get('ip-group-name')
    human_readable, entry_context, raw_res = \
        client.get_ip_group_entities(group_name, f'IP group entries for {group_name}')
    return_outputs(human_readable, entry_context, raw_res)


@logger
def ip_group_remove_entries_command(client, args):
    group_name = args.get('ip-group-name')
    raw_res = client.do_request('DELETE', f'conf/ipGroups/{group_name}/clear')
    return_outputs(f'The IP group {group_name} is now empty', {}, raw_res)


@logger
def sites_list_command(client, args):
    raw_res = client.do_request('GET', 'conf/sites')
    sites = [{'Name': site} for site in raw_res.get('sites', [])]

    human_readable = tableToMarkdown('All sites in the system', sites, removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Site(val.Name===obj.Name)': sites}
    return_outputs(human_readable, entry_context, raw_res)


@logger
def server_groups_list_command(client, args):
    site = args.get('site-name')
    raw_res = client.do_request('GET', f'conf/serverGroups/{site}')
    server_groups = []
    if raw_res.get('server-groups'):
        server_groups = raw_res['server-groups']
        for i, element in enumerate(server_groups):
            server_groups[i] = {'Name': server_groups[i], 'SiteName': site}

    human_readable = tableToMarkdown(f'Server groups in {site}', server_groups, removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.ServerGroup(val.Name===obj.Name)': server_groups}
    return_outputs(human_readable, entry_context, raw_res)


@logger
def server_group_policies_list_command(client, args):
    site = args.get('site-name')
    server_group = args.get('server-group-name')
    raw_res = client.do_request('GET', f'conf/serverGroups/{site}/{server_group}/securityPolicies')
    policies = []

    for policy in raw_res:
        policies.append({'System': policy.get('system'),
                         'PolicyName': policy.get('policy-name'),
                         'PolicyType': policy.get('policy-type'),
                         'ServerGroup': server_group,
                         'SiteName': site})

    human_readable = tableToMarkdown(f'Policies for {server_group}', policies, removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.SecurityPolicy(val.PolicyName===obj.PolicyName)': policies}
    return_outputs(human_readable, entry_context, raw_res)


@logger
def custom_policy_list_command(client, args):
    raw_res = client.do_request('GET', 'conf/policies/security/webServiceCustomPolicies')
    policies = []
    if raw_res.get('customWebPolicies'):
        policies = raw_res['customWebPolicies']
        for i, element in enumerate(policies):
            policies[i] = {'Name': policies[i]}

    human_readable = tableToMarkdown('Custom web policies', policies, removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.CustomWebPolicy(val.Name===obj.Name)': policies}
    return_outputs(human_readable, entry_context, raw_res)


@logger
def get_custom_policy_command(client, args):
    policy_name = args.get('policy-name')
    human_readable, entry_context, raw_res = \
        client.get_custom_policy_outputs(policy_name, f'Policy data for {policy_name}')
    return_outputs(human_readable, entry_context, raw_res)


@logger
def create_ip_group_command(client, args):
    group_name = args.get('group-name')
    body = generate_ip_groups_entries(args)
    client.do_request('POST', f'conf/ipGroups/{group_name}', json_data=body)
    human_readable, entry_context, raw_res = \
        client.get_ip_group_entities(group_name, f'Group {group_name} created successfully')
    return_outputs(human_readable, entry_context, raw_res)


@logger
def update_ip_group_command(client, args):
    group_name = args.get('group-name')
    body = generate_ip_groups_entries(args)
    client.do_request('PUT', f'conf/ipGroups/{group_name}/data', json_data=body)
    human_readable, entry_context, raw_res = \
        client.get_ip_group_entities(group_name, f'Group {group_name} updated successfully')
    return_outputs(human_readable, entry_context, raw_res)


@logger
def delete_ip_group_command(client, args):
    group_name = args.get('group-name')
    raw_res = client.do_request('DELETE', f'conf/ipGroups/{group_name}')
    return_outputs(f'Group {group_name} deleted successfully', {}, raw_res)


@logger
def create_custom_policy_command(client, args):
    policy_name = args.get('policy-name')
    site = args.get('site-name-to-apply')
    server_group = args.get('server-group-name-to-apply')
    web_service = args.get('web-service-name-to-apply')
    match_criteria_json = args.get('match-criteria-json')

    body = generate_policy_data_body(args)

    if match_criteria_json and not isinstance(match_criteria_json, dict):
        try:
            match_criteria_json = json.loads(match_criteria_json)
        except Exception:
            raise Exception(f'Failed to parse match-criteria-json as JSON data,'
                            f' received object:\n{match_criteria_json}')

        body['matchCriteria'] = match_criteria_json
    else:
        body = generate_match_criteria(body, args)

    body['applyTo'] = [{'siteName': site, 'serverGroupName': server_group, 'webServiceName': web_service}]

    client.do_request('POST', f'conf/policies/security/webServiceCustomPolicies/{policy_name}', json_data=body)
    human_readable, entry_context, raw_res = \
        client.get_custom_policy_outputs(policy_name, f'Policy {policy_name} created successfully')
    return_outputs(human_readable, entry_context, raw_res)


@logger
def update_custom_policy_command(client, args):
    policy_name = args.get('policy-name')
    site = args.get('site-name-to-apply')
    server_group = args.get('server-group-name-to-apply', '')
    web_service = args.get('web-service-name-to-apply', '')
    apply_operation = args.get('apply-operation', '')
    match_criteria_json = args.get('match-criteria-json')

    body = generate_policy_data_body(args)

    if match_criteria_json and not isinstance(match_criteria_json, dict):
        try:
            match_criteria_json = json.loads(match_criteria_json)
        except Exception:
            raise DemistoException(f'Failed to parse match-criteria-json as JSON data,'
                                   f' received object:\n{match_criteria_json}')

        body['matchCriteria'] = match_criteria_json
    else:
        body = generate_match_criteria(body, args)

    if apply_operation:
        body['applyTo'] = [{'operation': apply_operation, 'siteName': site, 'serverGroupName': server_group,
                           'webServiceName': web_service}]

    client.do_request('PUT', f'conf/policies/security/webServiceCustomPolicies/{policy_name}', json_data=body)
    human_readable, entry_context, raw_res = \
        client.get_custom_policy_outputs(policy_name, f'Policy {policy_name} updated successfully')
    return_outputs(human_readable, entry_context, raw_res)


@logger
def delete_custom_policy_command(client, args):
    policy_name = args.get('policy-name')
    raw_res = client.do_request('DELETE', f'conf/policies/security/webServiceCustomPolicies/{policy_name}')
    return_outputs(f'Policy {policy_name} deleted successfully', {}, raw_res)


def main():
    params = demisto.params()
    # get the service API url
    base_url = params.get('url')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    credentials = params.get('credentials')
    username = credentials['identifier'] if credentials else ''
    password = credentials['password'] if credentials else ''

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)
        command = demisto.command()
        args = demisto.args()
        commands = {'test-module': test_module,
                    'imperva-waf-ip-group-list': ip_group_list_command,
                    'imperva-waf-ip-group-list-entries': ip_group_list_entries_command,
                    'imperva-waf-ip-group-remove-entries': ip_group_remove_entries_command,
                    'imperva-waf-sites-list': sites_list_command,
                    'imperva-waf-server-group-list': server_groups_list_command,
                    'imperva-waf-server-group-list-policies': server_group_policies_list_command,
                    'imperva-waf-web-service-custom-policy-list': custom_policy_list_command,
                    'imperva-waf-web-service-custom-policy-get': get_custom_policy_command,
                    'imperva-waf-ip-group-create': create_ip_group_command,
                    'imperva-waf-ip-group-update-entries': update_ip_group_command,
                    'imperva-waf-ip-group-delete': delete_ip_group_command,
                    'imperva-waf-web-service-custom-policy-create': create_custom_policy_command,
                    'imperva-waf-web-service-custom-policy-update': update_custom_policy_command,
                    'imperva-waf-web-service-custom-policy-delete': delete_custom_policy_command,
                    }

        if command in commands:
            commands[command](client, args)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions
    except Exception as e:
        return_error(f'Unexpected error: {str(e)}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
