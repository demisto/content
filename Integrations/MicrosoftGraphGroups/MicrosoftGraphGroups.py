from CommonServerPython import *

''' IMPORTS '''
from typing import Dict, Tuple, Optional
import urllib3
import requests
from datetime import datetime
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
INTEGRATION_NAME = 'Microsoft Graph Groups'
INTEGRATION_CONTEXT_NAME = 'MSGraphGroups'
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-groups'


def camel_case_to_readable(text: str) -> str:
    """
    'camelCase' -> 'Camel Case'
    """
    if text == 'id':
        return 'ID'
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_outputs(groups_data: Dict[str, str]) -> Tuple[dict, dict]:
    """
    Parse group data as received from Microsoft Graph API into Demisto's conventions
    """
    fields_to_drop = ['@odata.context', '@odata.nextLink', '@odata.deltaLink', '@odata.type', '@removed',
                      'resourceProvisioningOptions', 'securityIdentifier', 'onPremisesSecurityIdentifier',
                      'onPremisesNetBiosName', 'onPremisesProvisioningErrors', 'onPremisesSamAccountName',
                      'resourceBehaviorOptions', 'creationOptions', 'preferredDataLocation']
    if isinstance(groups_data, list):
        groups_readable, groups_outputs = [], []
        for group_data in groups_data:
            group_readable = {camel_case_to_readable(i): j for i, j in group_data.items() if i not in fields_to_drop}
            if '@removed' in group_data:
                group_readable['Status'] = 'deleted'
            groups_readable.append(group_readable)
            groups_outputs.append({k.replace(' ', ''): v for k, v in group_readable.copy().items()})

        return groups_readable, groups_outputs

    else:
        group_readable = {camel_case_to_readable(i): j for i, j in groups_data.items() if i not in fields_to_drop}
        if '@removed' in groups_data:
            group_readable['Status'] = 'deleted'
        group_outputs = {k.replace(' ', ''): v for k, v in group_readable.copy().items()}

        return group_readable, group_outputs


def epoch_seconds() -> int:
    """
    Return the number of seconds for return current date.
    """
    return int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """

    Args:
        content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key (str): encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)

    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


class Client(BaseClient):
    def __init__(self, base_url: str, tenant: str, auth_and_token_url: str, auth_id: str, token_retrieval_url: str,
                 enc_key: str, use_ssl: bool, proxies: dict):
        self.base_url = base_url
        self.tenant = tenant
        self.auth_and_token_url = auth_and_token_url
        self.auth_id = auth_id
        self.token_retrieval_url = token_retrieval_url
        self.enc_key = enc_key
        self.use_ssl = use_ssl
        self.proxies = proxies

    def get_access_token(self):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if epoch_seconds() < valid_until:
                return access_token
        headers = {'Accept': 'application/json'}

        dbot_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            data=json.dumps({
                'app_name': APP_NAME,
                'registration_id': self.auth_id,
                'encrypted_token': get_encrypted(self.tenant, self.enc_key)
            }),
            verify=self.use_ssl
        )
        if dbot_response.status_code not in {200, 201}:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    dbot_response.status_code, dbot_response.reason, dbot_response.text))
                err_response = dbot_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = dbot_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Demistobot server did not contain the expected content.'
            )
        access_token = parsed_response.get('access_token')
        expires_in = parsed_response.get('expires_in', 3595)
        time_now = epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        demisto.setIntegrationContext({
            'access_token': access_token,
            'valid_until': time_now + expires_in
        })
        return access_token

    def http_request(self, method: str, url_suffix: str = None, params: Dict = None, body: Optional[str] = None,
                     next_link: str = None):
        """
        Generic request to Microsoft Graph
        """
        token = self.get_access_token()
        if next_link:
            url = next_link
        else:
            url = f'{self.base_url}{url_suffix}'

        response = requests.request(
            method,
            url,
            headers={
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            params=params,
            data=body,
            verify=self.use_ssl,
        )
        try:
            data = response.json() if response.text else {}
            if not response.ok:
                return_error(f'API call to MS Graph failed [{response.status_code}]'
                             f' - {demisto.get(data, "error.message")}')
            elif response.status_code == 206:  # 206 indicates Partial Content, reason will be in the warning header
                demisto.debug(str(response.headers))

            return data

        except TypeError as ex:
            demisto.debug(str(ex))
            return_error(f'Error in API call to Microsoft Graph, could not parse result [{response.status_code}]')

    def test_function(self):
        token = self.get_access_token()
        response = requests.get(
            self.base_url + 'groups',
            headers={
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            params={'$orderby': 'displayName'},
            verify=self.use_ssl
        )
        try:
            data = response.json() if response.text else {}
            if not response.ok:
                return_error(f'API call to MS Graph failed. Please check authentication related parameters.'
                             f' [{response.status_code}] - {demisto.get(data, "error.message")}')

            demisto.results('ok')

        except TypeError as ex:
            demisto.debug(str(ex))
            return_error(f'API call to MS Graph failed, could not parse result. '
                         f'Please check authentication related parameters. [{response.status_code}]')

    def list_groups(self, order_by: str = None, next_link: str = None) -> Dict:
        params = {'$orderby': order_by} if order_by else {}
        if next_link:  # pagination
            groups = self.http_request('GET', next_link=next_link)
        else:
            groups = self.http_request('GET', f'groups', params=params)

        return groups

    def get_group(self, id_: str) -> Dict:
        group = self.http_request('GET', f'groups/{id_}')
        return group

    def create_group(self, properties: Dict[str, str] = None) -> Dict:
        group = self.http_request('POST', 'groups', body=json.dumps(properties))
        return group

    def delete_group(self, group_id: str):
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.http_request('DELETE ', f'groups/{group_id}')

    def list_members(self, group_id: str, next_link: str = None) -> Dict:
        if next_link:  # pagination
            members = self.http_request('GET', next_link)
        else:
            members = self.http_request('GET', f'groups/{group_id}/members')

        return members

    def add_member(self, group_id: str, properties: Dict[str, str]):
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.http_request('POST', f'groups/{group_id}/members/$ref', body=json.dumps(properties))

    def remove_member(self, group_id: str, user_id: str):
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.http_request('DELETE', f'groups/{group_id}/members/{user_id}/$ref')


def test_function_command(client: Client, args: Dict):
    client.test_function()


def list_groups_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    order_by = args.get('order_by')
    next_link = args.get('next_link')
    groups = client.list_groups(order_by, next_link)

    groups_readable, groups_outputs = parse_outputs(groups['value'])
    human_readable = tableToMarkdown(name="Groups:", t=groups_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail'],
                                     removeNull=True)

    next_link_response = ''
    if '@odata.nextLink' in groups:
        next_link_response = groups['@odata.nextLink']

    if next_link_response:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID).NextLink': next_link_response,
                         f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': groups_outputs}
    else:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': groups_outputs}

    return human_readable, entry_context, groups


def get_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    id_ = str(args.get('id'))
    group = client.get_group(id_)

    group_readable, group_outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name="Groups:", t=group_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail',
                                              'Security Enabled', 'Visibility'],
                                     removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_outputs}
    return human_readable, entry_context, group


def create_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    required_properties = {
        'displayName': str(args.get('display_name')),
        'mailNickname': str(args.get('mail_nickname')),
        'mailEnabled': args.get('mail_enabled') == 'true',
        'securityEnabled': args.get('security_enabled')
    }

    # create the group
    group = client.create_group(required_properties)

    # display the new group and it's properties
    group_readable, group_outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name=f"{required_properties['displayName']} was created successfully:",
                                     t=group_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail',
                                              'Security Enabled', 'Mail Enabled'],
                                     removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_outputs}
    return human_readable, entry_context, group


def delete_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    group_id = str(args.get('group_id'))
    client.delete_group(group_id)

    # add a field that indicates that the group was deleted
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === {group_id}).Deleted': True}

    human_readable = f'Group: "{group_id}" was deleted successfully.'

    return human_readable, entry_context, NO_OUTPUTS


def list_members_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    group_id = str(args.get('group_id'))
    next_link = args.get('next_link')
    members = client.list_members(group_id, next_link)

    if not members['value']:
        human_readable = f'The group {group_id} has no members.'
        return human_readable, NO_OUTPUTS, NO_OUTPUTS
    else:
        members_readable, members_outputs = parse_outputs(members['value'])
        human_readable = tableToMarkdown(name=f'Group {group_id} members:', t=members_readable,
                                         headers=['ID', 'Display Name', 'Job Title', 'Mail'],
                                         removeNull=True)
        if '@odata.nextLink' in members:
            next_link_response = members['@odata.nextLink']
            entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': next_link_response,
                             f'{INTEGRATION_CONTEXT_NAME}(val.ID === {group_id}).Members': members_outputs}
        else:
            entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === {group_id}).Members': members_outputs}

    return human_readable, entry_context, members


def add_member_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    group_id = str(args.get('group_id'))
    user_id = str(args.get('user_id'))
    required_properties = {
        "@odata.id": f'https://graph.microsoft.com/v1.0/users/{user_id}'}
    client.add_member(group_id, required_properties)

    human_readable = f'User {user_id} was added to the Group {group_id} successfully.'
    return human_readable, NO_OUTPUTS, NO_OUTPUTS


def remove_member_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    group_id = str(args.get('group_id'))
    user_id = str(args.get('user_id'))
    client.remove_member(group_id, user_id)

    human_readable = f'User {user_id} was removed from the Group "{group_id}" successfully.'
    return human_readable, NO_OUTPUTS, NO_OUTPUTS


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    base_url = demisto.params().get('url').rstrip('/') + '/v1.0/'
    tenant = demisto.params().get('tenant_id')
    auth_and_token_url = demisto.params().get('auth_id').split('@')
    auth_id = auth_and_token_url[0]
    enc_key = demisto.params().get('enc_key')
    use_ssl = not demisto.params().get('insecure', False)
    proxies = handle_proxy()
    if len(auth_and_token_url) != 2:
        token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
    else:
        token_retrieval_url = auth_and_token_url[1]

    commands = {
        'test-module': test_function_command,
        'msgraph-groups-list-groups': list_groups_command,
        'msgraph-groups-get-group': get_group_command,
        'msgraph-groups-create-group': create_group_command,
        'msgraph-groups-delete-group': delete_group_command,
        'msgraph-groups-list-members': list_members_command,
        'msgraph-groups-add-member': add_member_command,
        'msgraph-groups-remove-member': remove_member_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(base_url, tenant, auth_and_token_url, auth_id, token_retrieval_url, enc_key, use_ssl, proxies)
        # Run the command
        human_readable, entry_context, raw_response = commands[command](client, demisto.args())
        # create a war room entry
        return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
