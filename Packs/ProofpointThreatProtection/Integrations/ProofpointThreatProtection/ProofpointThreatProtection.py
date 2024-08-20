import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' CONSTANTS '''


CTX_PREFIX = 'ProofpointThreatProtection'
OSL_HEADER = 'Organizational Safe List'
OBL_HEADER = 'Organizational Block List'
URL_SUFFIX_SAFELIST = '/emailProtection/modules/spam/orgSafeList'
URL_SUFFIX_BLOCKLIST = '/emailProtection/modules/spam/orgBlockList'
AUTH_HOST_BASE_URL = 'https://auth.proofpoint.com/v1'


''' INTEGRATION API CLIENT '''


class Client(BaseClient):
    """Client class to interact with the service API"""

    def get_args(self):
        return demisto.args()

    def get_auth_host(self):
        return AUTH_HOST_BASE_URL

    def get_shared_integration_context(self):
        return get_integration_context()

    def set_shared_integration_context(self, context):
        return set_integration_context(context)

    def get_access_token(self, client_id, client_secret):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the API key and secret.
        """
        # Check if there is an existing valid access token
        integration_context = self.get_shared_integration_context()
        if integration_context.get('access_token') and integration_context.get('expiry_time') > date_to_timestamp(datetime.now()):
            self._headers = {'Authorization' : f'Bearer {integration_context.get("access_token")}', 'Accept' : 'application/json'}
            return integration_context.get('access_token')
        else:
            try:
                res = self._http_request(
                    method='POST',
                    full_url=f'{self.get_auth_host()}/token',
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    data={
                        'grant_type': 'client_credentials',
                        'client_id': client_id,
                        'client_secret': client_secret
                    }
                )
                access_token = res.get('access_token', None)
                if access_token is not None:
                    expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                    expiry_time += res.get('expires_in', 0) * 1000 - 10
                    context = {
                        'access_token': access_token,
                        'expiry_time': expiry_time
                    }
                    self.set_shared_integration_context(context)
                    self._headers = {'Authorization' : f'Bearer {access_token}', 'Accept' : 'application/json'}
                    return res.get('access_token')

            except Exception as e:
                raise (Exception(f'Error occurred while creating an access token. '
                                 f'Please check the instance configuration.'
                                 f'\n\n{e.args[0]}'))

    def get_safelist(self, cluster_id):
        return self._http_request(
            'GET',
            url_suffix=URL_SUFFIX_SAFELIST,
            headers=self._headers,
            params={'clusterId': cluster_id}
        )

    def safelist_add_delete(self, cluster_id, args):
        import json
        self._headers.update({'Content-Type': 'application/json'})
        return self._http_request(
            'POST',
            resp_type='response',
            url_suffix=URL_SUFFIX_SAFELIST,
            headers=self._headers,
            params={'clusterId': cluster_id},
            data=json.dumps({
                'action': args.get('action'),
                'attribute': args.get('attribute'),
                'operator': args.get('operator'),
                'value': args.get('value'),
                'comment': args.get('comment')
            })
        )

    def get_blocklist(self, cluster_id):
        return self._http_request(
            'GET',
            url_suffix=URL_SUFFIX_BLOCKLIST,
            headers=self._headers,
            params={'clusterId': cluster_id}
        )

    def blocklist_add_delete(self, cluster_id, args):
        import json
        self._headers.update({'Content-Type': 'application/json'})
        return self._http_request(
            'POST',
            resp_type='response',
            url_suffix=URL_SUFFIX_BLOCKLIST,
            headers=self._headers,
            params={'clusterId': cluster_id},
            data=json.dumps({
                'action': args.get('action'),
                'attribute': args.get('attribute'),
                'operator': args.get('operator'),
                'value': args.get('value'),
                'comment': args.get('comment')
            })
        )


''' HELPER FUNCTIONS '''


def make_return_command_results(readable_op: str, op: dict) -> CommandResults:
    return_cr = CommandResults(readable_output=readable_op, outputs_prefix=CTX_PREFIX, outputs=op)

    return return_cr


''' COMMAND FUNCTIONS '''


def module_test_command(client: Client, cluster_id) -> str:
    client.get_blocklist(cluster_id)
    return 'ok'


def safelist_get_command(client: Client, cluster_id) -> CommandResults:
    res = client.get_safelist(cluster_id)
    res_rc = make_return_command_results(OSL_HEADER, {'Safelist': res.get('entries')})
    return res_rc


def safelist_add_delete_command(client: Client, cluster_id) -> CommandResults:
    res = client.safelist_add_delete(cluster_id, client.get_args())
    res_rc = make_return_command_results(OSL_HEADER, {'Safelist': res})
    return res_rc


def blocklist_get_command(client: Client, cluster_id) -> CommandResults:
    res = client.get_blocklist(cluster_id)
    res_rc = make_return_command_results(OBL_HEADER, {'Blocklist': res.get('entries')})
    return res_rc


def blocklist_add_delete_command(client: Client, cluster_id) -> CommandResults:
    res = client.blocklist_add_delete(cluster_id, client.get_args())
    res_rc = make_return_command_results(OBL_HEADER, {"Blocklist": res})
    return res_rc


'''         UPDATE COMMAND MAPPINGS
    (After command function declarations) '''

COMMANDS = {
    'test-module': module_test_command,
    'proofpoint-tp-safelist-get': safelist_get_command,
    'proofpoint-tp-blocklist-get': blocklist_get_command,
    'proofpoint-tp-safelist-add-or-delete-entry': safelist_add_delete_command,
    'proofpoint-tp-blocklist-add-or-delete-entry': blocklist_add_delete_command
}


''' MAIN FUNCTION '''


def parse_params(params: dict):
    client_id = params.get('credentials', {}).get('username', params.get('credentials', {}).get('identifier'))
    client_secret = params.get('credentials', {}).get('password')
    base_url = params.get('url')
    cluster_id = params.get('cluster_id')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    return client_id, client_secret, base_url, cluster_id, verify_certificate, proxy


def main() -> None:

    client_id, client_secret, base_url, cluster_id, verify_certificate, proxy = parse_params(demisto.params())

    command = demisto.command()

    try:
        if command in COMMANDS:
            client = Client(
                base_url=base_url,
                verify=verify_certificate,
                proxy=proxy)

            client.get_access_token(client_id, client_secret)
            return_results(COMMANDS[command](client, cluster_id))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
