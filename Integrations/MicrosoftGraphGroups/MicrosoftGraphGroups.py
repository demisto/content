from typing import Dict, Tuple, Optional, Any
from datetime import datetime
import base64
import urllib3
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_CONTEXT_NAME = 'MSGraphGroups'
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-groups'


def camel_case_to_readable(text: str) -> str:
    """'camelCase' -> 'Camel Case'

    Args:
        text: the text to transform

    Returns:
        A Camel Cased string.
    """
    if text == 'id':
        return 'ID'
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_outputs(groups_data: Dict[str, str]) -> Tuple[dict, dict]:
    """Parse group data as received from Microsoft Graph API into Demisto's conventions

    Args:
        groups_data: a dictionary containing the group data

    Returns:
        A Camel Cased dictionary with the relevant fields.
        groups_readable: for the human readable
        groups_outputs: for the entry context
    """
    # Unnecessary fields, dropping as to not load the incident context.
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
        ct_ = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct_)

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
        """Get the Microsoft Graph Access token from the instance token or generates a new one if needed.

        Returns:
            The access token.
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if epoch_seconds() < valid_until:
                return access_token

        dbot_response = requests.post(
            self.token_retrieval_url,
            headers={'Accept': 'application/json'},
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
                demisto.info(f'Authentication failure from server: {dbot_response.status_code}'
                             f' {dbot_response.reason} {dbot_response.text}')
                err_response = dbot_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                if server_msg:
                    msg += f' Server message: {server_msg}'
            except Exception as err:
                demisto.error(f'Failed parsing error response - Exception: {err}')
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
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        demisto.setIntegrationContext({
            'access_token': access_token,
            'valid_until': epoch_seconds() + expires_in
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

        try:
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
        except requests.ConnectionError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to Microsoft Graph.\n'
                            f'Check your Server URL parameter.\n\n{err}')

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
            raise Exception(f'Error in API call to Microsoft Graph, could not parse result [{response.status_code}]')

    def test_function(self):
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            ok if successful.
        """
        self.http_request('GET', 'groups', params={'$orderby': 'displayName'})
        demisto.results('ok')

    def list_groups(self, order_by: str = None, next_link: str = None) -> Dict:
        """Returns all groups by sending a GET request.

        Args:
            order_by: the group fields to order by the response.
            next_link: the link for the next page of results, if exists. see Microsoft documentation for more details.
                docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0
        Returns:
            Response from API.
        """
        params = {'$orderby': order_by} if order_by else {}
        if next_link:  # pagination
            groups = self.http_request('GET', next_link=next_link)
        else:
            groups = self.http_request('GET', 'groups', params=params)

        return groups

    def get_group(self, group_id: str) -> Dict:
        """Returns a single group by sending a GET request.

        Args:
            group_id: the group id.

        Returns:
            Response from API.
        """
        group = self.http_request('GET', f'groups/{group_id}')
        return group

    def create_group(self, properties: Dict[str, Optional[Any]]) -> Dict:
        """Create a single group by sending a POST request.

        Args:
            properties: the group properties.

        Returns:
            Response from API.
        """
        group = self.http_request('POST', 'groups', body=json.dumps(properties))
        return group

    def delete_group(self, group_id: str):
        """Delete a single group by sending a DELETE request.

        Args:
            group_id: the group id to delete.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.http_request('DELETE ', f'groups/{group_id}')

    def list_members(self, group_id: str, next_link: str = None) -> Dict:
        """List all group members by sending a GET request.

        Args:
            group_id: the group id to list its members.
            next_link: the link for the next page of results, if exists. see Microsoft documentation for more details.
                docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
        Returns:
            Response from API.
        """
        if next_link:  # pagination
            members = self.http_request('GET', next_link)
        else:
            members = self.http_request('GET', f'groups/{group_id}/members')

        return members

    def add_member(self, group_id: str, properties: Dict[str, str]):
        """Add a single member to a group by sending a POST request.
        Args:
            group_id: the group id to add the member to.
            properties: the member properties.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.http_request('POST', f'groups/{group_id}/members/$ref', body=json.dumps(properties))

    def remove_member(self, group_id: str, user_id: str):
        """Remove a single member to a group by sending a DELETE request.
        Args:
            group_id: the group id to add the member to.
            user_id: the user id to remove.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.http_request('DELETE', f'groups/{group_id}/members/{user_id}/$ref')


def test_function_command(client: Client, args: Dict):
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    client.test_function()


def list_groups_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all groups and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    order_by = args.get('order_by')
    next_link = args.get('next_link')
    groups = client.list_groups(order_by, next_link)

    groups_readable, groups_outputs = parse_outputs(groups['value'])

    next_link_response = ''
    if '@odata.nextLink' in groups:
        next_link_response = groups['@odata.nextLink']

    if next_link_response:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID).NextLink': next_link_response,
                         f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': groups_outputs}
        title = 'Groups (Note that there are more results. Please use the next_link argument to see them.):'
    else:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': groups_outputs}
        title = 'Groups:'

    human_readable = tableToMarkdown(name=title, t=groups_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail'],
                                     removeNull=True)

    return human_readable, entry_context, groups


def get_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get a group by group id and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    group = client.get_group(group_id)

    group_readable, group_outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name="Groups:", t=group_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail',
                                              'Security Enabled', 'Visibility'],
                                     removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(obj.ID === {group_id})': group_outputs}
    return human_readable, entry_context, group


def create_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create a group and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
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
    """Delete a group by group id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    client.delete_group(group_id)

    # get the group data from the context
    group_data = demisto.dt(demisto.context(), f'{INTEGRATION_CONTEXT_NAME}(val.ID === "{group_id}")')
    if type(group_data) is list:
        group_data = group_data[0]

    # add a field that indicates that the group was deleted
    group_data['Deleted'] = True  # add a field with the members to the group
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_data}

    human_readable = f'Group: "{group_id}" was deleted successfully.'
    return human_readable, entry_context, NO_OUTPUTS


def list_members_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """List a group members by group id. return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    next_link = args.get('next_link')
    members = client.list_members(group_id, next_link)

    if not members['value']:
        human_readable = f'The group {group_id} has no members.'
        return human_readable, NO_OUTPUTS, NO_OUTPUTS

    members_readable, members_outputs = parse_outputs(members['value'])

    # get the group data from the context
    group_data = demisto.dt(demisto.context(), f'{INTEGRATION_CONTEXT_NAME}(val.ID === "{group_id}")')
    if type(group_data) is list:
        group_data = group_data[0]

    if '@odata.nextLink' in members:
        next_link_response = members['@odata.nextLink']
        group_data['Members'] = members_outputs  # add a field with the members to the group
        group_data['Members']['NextLink'] = next_link_response
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_data}
        title = f'Group {group_id} members ' \
                f'(Note that there are more results. Please use the next_link argument to see them.):'
    else:
        group_data['Members'] = members_outputs  # add a field with the members to the group
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_data}
        title = f'Group {group_id} members:'

    human_readable = tableToMarkdown(name=title, t=members_readable,
                                     headers=['ID', 'Display Name', 'Job Title', 'Mail'],
                                     removeNull=True)

    return human_readable, entry_context, members


def add_member_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Add a member to a group by group id and user id. return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    user_id = str(args.get('user_id'))
    required_properties = {
        "@odata.id": f'https://graph.microsoft.com/v1.0/users/{user_id}'}
    client.add_member(group_id, required_properties)

    human_readable = f'User {user_id} was added to the Group {group_id} successfully.'
    return human_readable, NO_OUTPUTS, NO_OUTPUTS


def remove_member_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Remove a member from a group by group id and user id. return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    user_id = str(args.get('user_id'))
    client.remove_member(group_id, user_id)

    human_readable = f'User {user_id} was removed from the Group "{group_id}" successfully.'
    return human_readable, NO_OUTPUTS, NO_OUTPUTS


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

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
